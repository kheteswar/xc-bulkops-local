import forge from 'node-forge';

export interface ParsedCertificateSubject {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
}

export interface ParsedCertificate {
  subject: ParsedCertificateSubject;
  issuer: ParsedCertificateSubject;
  validFrom: Date;
  validTo: Date;
  serialNumber: string;
  sans: string[];
  isSelfSigned: boolean;
  fingerprint?: string;
}

/**
 * Extracts subject/issuer fields from a certificate
 */
const extractCertFields = (certEntity: forge.pki.CertificateField[]): ParsedCertificateSubject => {
  const getField = (shortName: string): string | undefined => {
    const field = certEntity.find((f: any) => f.shortName === shortName || f.name === shortName);
    return field?.value as string | undefined;
  };

  return {
    commonName: getField('CN') || 'Unknown',
    organization: getField('O'),
    organizationalUnit: getField('OU'),
    country: getField('C'),
    state: getField('ST'),
    locality: getField('L'),
  };
};

/**
 * Extracts Subject Alternative Names from certificate extensions
 */
const extractSANs = (cert: forge.pki.Certificate): string[] => {
  const sans: string[] = [];
  
  try {
    const sanExtension = cert.getExtension('subjectAltName') as any;
    if (sanExtension && sanExtension.altNames) {
      for (const altName of sanExtension.altNames) {
        // Type 2 = DNS, Type 7 = IP
        if (altName.type === 2 && altName.value) {
          sans.push(altName.value);
        } else if (altName.type === 7 && altName.ip) {
          sans.push(altName.ip);
        }
      }
    }
  } catch (e) {
    console.warn('[CertParser] Could not extract SANs:', e);
  }
  
  return sans;
};

/**
 * Calculates SHA-1 fingerprint of the certificate
 */
const calculateFingerprint = (cert: forge.pki.Certificate): string => {
  try {
    const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const md = forge.md.sha1.create();
    md.update(derBytes);
    const hex = md.digest().toHex().toUpperCase();
    // Format as XX:XX:XX:XX...
    return hex.match(/.{2}/g)?.join(':') || hex;
  } catch (e) {
    console.warn('[CertParser] Could not calculate fingerprint:', e);
    return '';
  }
};

/**
 * Parses an F5 XC certificate URL (string:///base64data) into readable certificate details
 */
export const parseCertificateUrl = (certUrl: string | undefined): ParsedCertificate | null => {
  // DEBUG 1: Check what we're receiving
  console.log("[CertParser] Input URL:", certUrl ? `${certUrl.substring(0, 50)}...` : 'undefined');

  if (!certUrl) {
    console.warn("[CertParser] Empty or undefined certificate URL");
    return null;
  }

  // Handle both 'string:///' prefix format and raw base64/PEM
  let pemData: string;
  
  try {
    if (certUrl.startsWith('string:///')) {
      // F5 XC format: string:///base64EncodedPEM
      const base64Data = certUrl.replace('string:///', '');
      
      // DEBUG 2: Check Base64 data length
      console.log("[CertParser] Base64 Length:", base64Data.length);
      
      // Decode Base64 to PEM
      pemData = atob(base64Data).trim();
    } else if (certUrl.includes('-----BEGIN CERTIFICATE-----')) {
      // Already PEM format
      pemData = certUrl.trim();
    } else {
      // Try treating as raw base64
      try {
        pemData = atob(certUrl).trim();
      } catch {
        console.warn("[CertParser] Could not decode certificate data");
        return null;
      }
    }

    // DEBUG 3: Check if PEM looks correct
    console.log("[CertParser] Decoded PEM Start:", pemData.substring(0, 50).replace(/\n/g, ' '));

    // Validate PEM format
    if (!pemData.includes('-----BEGIN CERTIFICATE-----')) {
      console.warn("[CertParser] Invalid PEM format - missing BEGIN marker");
      return null;
    }

    // Parse using node-forge
    const cert = forge.pki.certificateFromPem(pemData);

    // DEBUG 4: Check if Forge parsed it
    console.log("[CertParser] Forge Subject CN:", cert.subject.getField('CN')?.value);

    // Extract all certificate details
    const subject = extractCertFields(cert.subject.attributes);
    const issuer = extractCertFields(cert.issuer.attributes);
    const sans = extractSANs(cert);
    const fingerprint = calculateFingerprint(cert);

    // Check if self-signed (issuer matches subject)
    const isSelfSigned = cert.isIssuer(cert);

    const result: ParsedCertificate = {
      subject,
      issuer,
      validFrom: cert.validity.notBefore,
      validTo: cert.validity.notAfter,
      serialNumber: cert.serialNumber.toUpperCase(),
      sans,
      isSelfSigned,
      fingerprint,
    };

    console.log("[CertParser] Parse Success!", {
      cn: result.subject.commonName,
      validTo: result.validTo,
      sansCount: result.sans.length
    });

    return result;

  } catch (err) {
    // CRITICAL DEBUG: Log the actual parsing error
    console.error("[CertParser] CRASH:", err instanceof Error ? err.message : err);
    return null;
  }
};