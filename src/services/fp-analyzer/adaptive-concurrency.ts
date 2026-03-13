/**
 * Adaptive Concurrency Controller
 *
 * State machine with three states that automatically tunes worker count
 * and request delays based on API rate limit responses (429s).
 *
 * GREEN  → Full speed, no delays. Ramp UP concurrency after consecutive successes.
 * YELLOW → Light throttle (200ms delay). Halved concurrency. Ramp to GREEN after successes.
 * RED    → Heavy throttle (2000ms delay). Minimum concurrency. Cool down before recovering.
 *
 * ONE controller is shared across ALL workers per phase.
 * A 429 on any worker immediately affects everyone (F5 XC rate limits are per-tenant).
 */

export type RateLimitState = 'green' | 'yellow' | 'red';

export interface AdaptiveConcurrencyConfig {
  initialConcurrency: number;
  minConcurrency: number;
  maxConcurrency: number;
  rampUpAfterSuccesses: number;
  rampDownFactor: number;
  yellowDelayMs: number;
  redDelayMs: number;
  redCooldownMs: number;
}

const DEFAULT_CONFIG: AdaptiveConcurrencyConfig = {
  initialConcurrency: 3,
  minConcurrency: 1,
  maxConcurrency: 12,
  rampUpAfterSuccesses: 10,
  rampDownFactor: 0.5,
  yellowDelayMs: 200,
  redDelayMs: 2000,
  redCooldownMs: 10000,
};

export class AdaptiveConcurrencyController {
  private config: AdaptiveConcurrencyConfig;
  private currentConcurrency: number;
  private state: RateLimitState = 'green';
  private consecutiveSuccesses = 0;
  private lastRateLimitTime = 0;
  private totalRequests = 0;
  private totalRateLimits = 0;
  private startTime = Date.now();

  onStateChange?: (state: RateLimitState, concurrency: number) => void;

  constructor(config: Partial<AdaptiveConcurrencyConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.currentConcurrency = this.config.initialConcurrency;
  }

  get concurrency(): number {
    return this.currentConcurrency;
  }

  getState(): RateLimitState {
    return this.state;
  }

  getRequestDelay(): number {
    switch (this.state) {
      case 'green': return 0;
      case 'yellow': return this.config.yellowDelayMs;
      case 'red': return this.config.redDelayMs;
    }
  }

  recordSuccess(): void {
    this.totalRequests++;
    this.consecutiveSuccesses++;

    // RED → YELLOW after cooldown period
    if (this.state === 'red' && (Date.now() - this.lastRateLimitTime) > this.config.redCooldownMs) {
      this.transitionTo('yellow');
    }

    // YELLOW → GREEN after consistent successes
    if (this.state === 'yellow' && this.consecutiveSuccesses >= this.config.rampUpAfterSuccesses) {
      this.transitionTo('green');
    }

    // GREEN: try ramping up concurrency
    if (this.state === 'green' && this.consecutiveSuccesses >= this.config.rampUpAfterSuccesses) {
      this.consecutiveSuccesses = 0;
      if (this.currentConcurrency < this.config.maxConcurrency) {
        this.currentConcurrency++;
        this.onStateChange?.('green', this.currentConcurrency);
      }
    }
  }

  recordRateLimit(): void {
    this.totalRequests++;
    this.totalRateLimits++;
    this.consecutiveSuccesses = 0;
    this.lastRateLimitTime = Date.now();

    const newConc = Math.max(
      this.config.minConcurrency,
      Math.floor(this.currentConcurrency * this.config.rampDownFactor),
    );

    if (this.state === 'green') {
      this.currentConcurrency = newConc;
      this.transitionTo('yellow');
    } else if (this.state === 'yellow') {
      this.currentConcurrency = this.config.minConcurrency;
      this.transitionTo('red');
    }
    // Already RED — stay RED, reset cooldown timer (lastRateLimitTime updated above)

    this.onStateChange?.(this.state, this.currentConcurrency);
  }

  recordError(): void {
    this.totalRequests++;
    this.consecutiveSuccesses = 0;
  }

  private transitionTo(newState: RateLimitState): void {
    this.state = newState;
    this.consecutiveSuccesses = 0;
  }

  getStats(): {
    state: RateLimitState;
    concurrency: number;
    totalRequests: number;
    rateLimitHits: number;
    rateLimitPct: string;
    requestsPerSecond: string;
    elapsedMs: number;
  } {
    const elapsed = Date.now() - this.startTime;
    const elapsedSec = elapsed / 1000;
    return {
      state: this.state,
      concurrency: this.currentConcurrency,
      totalRequests: this.totalRequests,
      rateLimitHits: this.totalRateLimits,
      rateLimitPct: this.totalRequests > 0
        ? ((this.totalRateLimits / this.totalRequests) * 100).toFixed(1) + '%'
        : '0%',
      requestsPerSecond: elapsedSec > 0
        ? (this.totalRequests / elapsedSec).toFixed(1)
        : '0',
      elapsedMs: elapsed,
    };
  }
}
