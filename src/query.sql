SELECT
sub.certificate_id certificate_id,
x509_issuerName(sub.certificate) issuer_name,
x509_commonName(sub.certificate) common_name,
x509_notBefore(sub.certificate) not_before,
x509_notAfter(sub.certificate) not_after,
encode(digest(sub.certificate, 'sha256'), 'hex') sha256_fingerprint,
sans.sans sans
FROM
	(
	SELECT min(certificate_id) certificate_id, certificate
	FROM certificate_and_identities
	WHERE plainto_tsquery('certwatch', '{domain}') @@ identities(certificate)
	AND x509_notAfter(certificate) > now() AT TIME ZONE 'UTC'
	AND x509_hasextension(certificate, 'CT Precertificate Poison') IS FALSE
	GROUP BY certificate
	LIMIT 10000
	) sub,
LATERAL (SELECT string_agg(DISTINCT san, ' ') AS sans FROM x509_altNames(sub.certificate) as san) sans
