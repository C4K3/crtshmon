SELECT
min(sub.certificate_id) certificate_id,
array_to_string(array_agg(DISTINCT sub.name_value), ' ') name_values,
x509_issuerName(sub.CERTIFICATE) issuer_name,
x509_commonName(sub.CERTIFICATE) common_name,
x509_notBefore(sub.CERTIFICATE) not_before,
x509_notAfter(sub.CERTIFICATE) not_after,
encode(digest(sub.CERTIFICATE, 'sha256'), 'hex') sha256_fingerprint
FROM
	(
	SELECT *
	FROM certificate_and_identities
	WHERE plainto_tsquery('certwatch', '{domain}') @@ identities(certificate)
	AND x509_notAfter(certificate) > now() AT TIME ZONE 'UTC'
	AND x509_hasextension(certificate, 'CT Precertificate Poison') IS FALSE
	LIMIT 10000
	) sub
GROUP BY sub.certificate
