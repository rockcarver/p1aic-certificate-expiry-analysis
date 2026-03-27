/**
 * Certificate Expiry Analysis Script for Ping Identity's PS Team
 *
 * This script is designed to run in a P1AIC environment and performs the following functions:
 * 1. Fetches all secrets from the Google Secret Manager Secret Store Provider and identifies those that contain PEM-encoded certificates.
 * 2. Parses the certificates to extract their attributes (Subject, Issuer, NotBefore, NotAfter, Serial Number).
 * 3. Checks the expiry status of each certificate against the current date and a configurable warning threshold (e.g., 10 days).
 * 4. Correlates certificates to their associated SAML entities (IDPs or SPs) based on the realm configuration, particularly for
 * hosted providers where secret IDs are directly referenced.
 * 5. Generates a report of all certificates, highlighting those that are expired or expiring soon, and sends a notification email to
 * configured recipients with the details.
 * The script uses a configuration object that can be overridden by an ESV JSON object for flexibility across different environments.
 * It also includes robust logging for traceability and error handling.
 * Note: This script assumes that the service account used for authentication has the necessary permissions to read secrets from ESV,
 * access realm configuration, and send emails through P1AIC email service.
 * Author: Sandeep Chaturvedi (sandeep.chaturvedi@pingidentity.com)
 */

/**
 * ESV key where the JSON configuration object is stored
 * The JSON object should have the same structure as the default config object defined below, and can override any of the default values.
 * This allows for flexible configuration without modifying the script code.
 */
var configEsv = 'esv.pingps.cert.status.config';

/**
 * Default configuration object defining the behavior of the certificate expiry check.
 */
var config = {
  onlySendEmailIfActionNeeded: false, // if true, only sends email if there are certs that are expired or expiring soon,
  // otherwise sends email every time the script runs with the status of all certs
  onlyIncludeProblematicCertsInEmail: false, // if true, only includes certs that are expired or expiring soon in
  // the notification email, otherwise includes all certs in the email
  emailTemplate: 'pingPsCertificateStatusCheck', // the name of the email template to use when sending notifications
  emailRecipients: 'sandeep.chaturvedi@pingidentity.com', // comma separated list of email addresses to send cert expiry warnings to
  emailFromAddress: 'sandeep.chaturvedi@pingidentity.com', // email address to use in the from field when sending cert expiry warnings
  warningDays: 10, // number of days before expiry to start sending warnings
  serviceAccountId: 'a7a656e2-db72-4324-b402-5b68dce6cab8', // service account client id to use for getting access token to call
  // ESV and get secret values
  serviceAccountJwk: 'only-to-be-resolved-from-esv', // the JWK for the service account, should be stored in ESV and
  // referenced here, e.g. 'esv.pingps.service.account.jwk'
  scope: 'fr:am:* fr:idc:esv:read', // scope to use for access token when calling ESV, should have at least read access to
  // secrets in ESV and realm config in AM
  envFqdn: 'openam-yyc-dev.forgeblocks.com', // fqdn of the environment, used for getting access token and calling ESV,
  // e.g. 'openam-yyc-dev.forgeblocks.com'
  logprefix: 'pingpslog: Ping PS Certificate Expiry Checking System: ' // prefix to prepend to all log messages for easier tracing in logs
};

/**
 * Custom logger utility wrapping the native ForgeRock logger.
 * Prepends a standard prefix to all log messages to make tracing easier.
 */
var log = {
  prefix: config.logprefix + ' ',
  _doLog: function (level, originalArgs) {
    var args = Array.prototype.slice.call(originalArgs, 0);
    if (args.length > 0) {
      args[0] = this.prefix + args[0];
    }
    try {
      logger[level].apply(logger, args);
    } catch (e) {
      logger.error(config.logprefix + ' FAILED TO LOG: ' + e);
    }
  },
  debug: function (message /*, ...args */) {
    this._doLog('debug', arguments);
  },
  info: function (message /*, ...args */) {
    this._doLog('info', arguments);
  },
  warn: function (message /*, ...args */) {
    this._doLog('warn', arguments);
  },
  error: function (message /*, ...args */) {
    this._doLog('error', arguments);
  }
};

/**
 * Resolves an ESV (Environment Secrets and Variables) key to its actual value.
 * If the string doesn't start with 'esv.', it assumes it's a raw value and returns it directly.
 */
function resolveEsv(esvKey) {
  log.debug('Resolving esv {}', esvKey);
  if (typeof esvKey == 'string' && esvKey.startsWith('esv.')) {
    var esvValue = identityServer.getProperty(esvKey);
    if (!esvValue) {
      log.error("Couldn't get value from esv {}", esvKey);
      throw "Couldn't get value from esv " + esvKey;
    }
    return esvValue;
  }
  return esvKey; // Return raw value if not an ESV reference
}

function resolveConfigObject() {
  var configObject = identityServer.getProperty(configEsv);
  if (!configObject) {
    log.error("Couldn't get config object from esv {}", configEsv);
    throw "Couldn't get config object from esv " + configEsv;
  }
  try {
    var parsedConfig = JSON.parse(configObject);
    for (var c in parsedConfig) {
      if (typeof parsedConfig[c] == 'string' && parsedConfig[c].startsWith('esv.')) {
        parsedConfig[c] = identityServer.getProperty(parsedConfig[c]);
      }
    }
    Object.assign(config, parsedConfig); // Override default config with values from ESV
  } catch (e) {
    log.error('Error parsing config object from esv {}: {}', configEsv, e);
    throw 'Error parsing config object from esv ' + configEsv + ': ' + e;
  }
  var configCopy = JSON.parse(JSON.stringify(config));
  configCopy.serviceAccountJwk = '***redacted for security***'; // redact sensitive info from logs
  log.debug('Resolved configuration: {}', JSON.stringify(configCopy));
}

/**
 * Retrieves a list of all secret IDs from the Google Secret Manager Secret Store Provider.
 */
function getAllSecretIds(token) {
  var params = {
    url: `https://${config.envFqdn}/am/json/realms/root/realms/alpha/realm-config/secrets/stores/GoogleSecretManagerSecretStoreProvider/ESV/mappings?_action=schema`,
    method: 'GET',
    authenticate: {
      type: 'bearer',
      token: token
    }
  };
  var sIdRet = openidm.action('external/rest', 'call', params);
  if (sIdRet.properties && sIdRet.properties.secretId && sIdRet.properties.secretId.enum) {
    var ids = sIdRet.properties.secretId.enum;
    log.debug('number of secret ids {}', ids.length);
    return ids;
  }
  return [];
}

/**
 * Retrieves the mapping configuration that links logical AM secret IDs to their underlying ESV aliases.
 * Returns a dictionary keyed by secretId.
 */
function getAllSecretIdToEsvMappings(token) {
  try {
    log.debug('getting all secret id to esv mappings, token: {}', token);
    var params = {
      url: `https://${config.envFqdn}/am/json/realms/root/realms/alpha/realm-config/secrets/stores/GoogleSecretManagerSecretStoreProvider/ESV/mappings?_queryFilter=true`,
      method: 'GET',
      authenticate: {
        type: 'bearer',
        token: token
      }
    };
    var sidMapping = {};
    var sidMappingRet = openidm.action('external/rest', 'call', params);
    if (sidMappingRet.resultCount > 0) {
      log.info('found {} secret id to esv mapping entries', sidMappingRet.resultCount);
      for (var s of sidMappingRet.result) {
        log.debug('secret id to esv mapping: {} -> {}', s.secretId, s.aliases[0]);
        sidMapping[s.secretId] = s.aliases[0].replace(/-/g, '.');
      }
      return sidMapping;
    }
    return null;
  } catch (e) {
    log.error('Error getting secret id to esv mappings: {}', e);
    return null;
  }
}

/**
 * Generates an OAuth2 access token for the configured service account.
 * Uses a private key JWT for client authentication (urn:ietf:params:oauth:client-assertion-type:jwt-bearer).
 */
function getAccessToken() {
  var serviceAccountClientId = 'service-account';
  var maxAttempts = 3;
  var jwtValiditySeconds = 10;

  // Import required Java classes for cryptographic and JWT operations
  var javaLibs = JavaImporter(
    org.forgerock.json.jose.builders.JwtBuilderFactory,
    org.forgerock.json.jose.jwt.JwtClaimsSet,
    org.forgerock.json.jose.jws.JwsAlgorithm,
    org.forgerock.json.jose.jws.SignedJwt,
    org.forgerock.json.jose.jws.handlers.SecretRSASigningHandler,
    org.forgerock.json.jose.jwk.RsaJWK,
    org.forgerock.json.JsonValue,
    javax.crypto.spec.SecretKeySpec,
    org.forgerock.secrets.SecretBuilder,
    org.forgerock.secrets.keys.SigningKey,
    java.time.temporal.ChronoUnit,
    java.time.Clock,
    java.util.UUID
  );

  // Helper to load the private key and build a SigningKey object
  function getServiceAccountCredentials() {
    var serviceAccountId = config.serviceAccountId;
    var jwk = config.serviceAccountJwk;

    if (!jwk) {
      log.error('Couldn not get private key from esv: {}', config.privateKeyEsv);
      throw 'Couldn not get private key from esv ' + config.privateKeyEsv;
    }

    // Parse the JWK JSON into an RSA Private Key
    var serviceAccountJwk = javaLibs.RsaJWK.parse(javaLibs.JsonValue(JSON.parse(jwk))).toRSAPrivateKey();
    var secretBuilder = new javaLibs.SecretBuilder();
    secretBuilder.secretKey(serviceAccountJwk).stableId(serviceAccountId).expiresIn(1, javaLibs.ChronoUnit.MINUTES, javaLibs.Clock.systemUTC());
    var signingKey = new javaLibs.SigningKey(secretBuilder);

    return {
      serviceAccountId: serviceAccountId,
      signingKey: signingKey
    };
  }

  // Helper to build and sign the client assertion JWT
  function buildJwt(credentials, audience) {
    var iat = new Date().getTime();
    var exp = new Date(iat + jwtValiditySeconds * 1000);
    var jwtClaims = new javaLibs.JwtClaimsSet();

    jwtClaims.setIssuer(credentials.serviceAccountId);
    jwtClaims.setSubject(credentials.serviceAccountId);
    jwtClaims.addAudience(audience);
    jwtClaims.setExpirationTime(exp);
    jwtClaims.setJwtId(javaLibs.UUID.randomUUID());

    var signingHandler = new javaLibs.SecretRSASigningHandler(credentials.signingKey);
    var jwt = new javaLibs.JwtBuilderFactory().jws(signingHandler).headers().alg(javaLibs.JwsAlgorithm.RS256).done().claims(jwtClaims).build();
    return jwt;
  }

  // Main logic to request the token from AM
  function getNewAccessToken() {
    var credentials = getServiceAccountCredentials();
    var response = null;
    var tenant = config.envFqdn; // Note: double resolution removed, using resolved config value
    var tokenEndpoint = `https://${tenant}/am/oauth2/access_token`;

    log.debug('Getting Access Token from endpoint {}', tokenEndpoint);
    var assertionJwt = buildJwt(credentials, tokenEndpoint);
    log.debug('Got assertion JWT {}', assertionJwt);

    var attempt = 0;
    while (!response && attempt < maxAttempts) {
      attempt++;
      log.debug('Attempt {} of {}', attempt, maxAttempts);
      try {
        var body = 'grant_type='.concat(encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer')).concat('&client_id=').concat(encodeURIComponent(serviceAccountClientId)).concat('&assertion=').concat(encodeURIComponent(assertionJwt)).concat('&scope=').concat(encodeURIComponent(config.scope));

        var params = {
          forceWrap: true,
          url: tokenEndpoint,
          body: body,
          method: 'POST',
          headers: {
            'Cache-Control': 'no-cache',
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        };

        response = openidm.action('external/rest', 'call', params);
        if (response.code !== 200) {
          log.warn('Unable to acquire Access Token. HTTP Result: {}', response.getStatus());
          response = null;
        }
      } catch (e) {
        log.error('Failure calling access token endpoint: {} exception: ' + e, tokenEndpoint);
      }
    }

    if (!response) {
      log.error('Failure to get access token');
      throw 'Failure to get access token';
    }

    try {
      var responseJson = response.body;
      log.debug('Response content {}', responseJson);
      var oauth2response = JSON.parse(responseJson);
      return oauth2response.access_token;
    } catch (e) {
      log.error('Error getting access token from response: {}', e);
      throw 'Error getting access token from response: ' + e;
    }
  }

  return getNewAccessToken();
}

/**
 * Builds an HTML table reporting the status of all analyzed certificates and emails it out.
 */
function sendNotificationEmail(allCerts) {
  var totalCertsEvaluated = 0;
  var totalCertsExpiringSoon = 0;
  var totalCertsExpired = 0;

  log.info('sending notification email to {}', config.emailRecipients);
  try {
    var rows = [];
    for (var c in allCerts) {
      var cert = allCerts[c];
      totalCertsEvaluated++;
      if (cert.status === -1) totalCertsExpired++;
      else if (cert.status > 0) totalCertsExpiringSoon++;
      if (config.onlyIncludeProblematicCertsInEmail && cert.status === 0) {
        continue; // skip certs that are not expired or expiring soon if config is set to only include problematic certs
      }
      var row = {
        expired: cert.status === -1 ? true : false,
        expiringSoon: cert.status > 0 ? true : false,
        expiryDays: cert.status > 0 ? cert.status : null,
        esvSecretId: Object.keys(cert.esvs || {}).join(', '),
        subject: cert.subject,
        issuer: cert.issuer,
        serial: cert.serial,
        expires: cert.notAfter,
        samlEntities: cert.samlEntity ? cert.samlEntity.map((e) => `[${e.id} ${e.type} (${e.use})]`).join('; ') : 'N/A'
      };
      log.debug('row: {}', row);
      rows.push(row);
    }
    log.info('Total certs evaluated: {}, Expired certs: {}, Expiring soon certs: {}', totalCertsEvaluated, totalCertsExpired, totalCertsExpiringSoon);

    emailParams = {
      object: {
        title: 'Certificate Expiry Check Report for ' + config.envFqdn,
        env: config.envFqdn,
        onlyIssues: config.onlyIncludeProblematicCertsInEmail,
        totalCertsEvaluated: totalCertsEvaluated,
        totalCertsExpired: totalCertsExpired,
        totalCertsExpiringSoon: totalCertsExpiringSoon,
        rows: rows
      },
      templateName: config.emailTemplate,
      from: config.emailFromAddress,
      to: config.emailRecipients,
      subject: 'Certificate Expiry Check Report for ' + config.envFqdn
    };

    // Use P1AIC external email service to send the payload
    openidm.action('external/email', 'sendTemplate', emailParams);
    log.info('SENT notification email to {}', emailParams.to);
  } catch (e) {
    log.error('ERROR in sending notification email to {}: ' + e, config.emailRecipients);
  }
}

/**
 * Retrieves all SAML 2.0 entity configurations (hosted and remote) from the realm.
 */
function getRealmSamlEntities(token, realm) {
  var params = {
    url: `https://${config.envFqdn}/am/json/realms/root/realms/${realm}/realm-config/saml2?_queryFilter=true&_pageSize=10000`,
    method: 'GET',
    authenticate: {
      type: 'bearer',
      token: token
    }
  };
  var entitiesRet = openidm.action('external/rest', 'call', params);
  return entitiesRet.result || [];
}

/**
 * Combines hosted and remote SAML entities from alpha and bravo realms into a single list for processing.
 */
function getAllSamlEntities(token) {
  var alphaEntities = getRealmSamlEntities(token, 'alpha');
  var bravoEntities = getRealmSamlEntities(token, 'bravo');
  return alphaEntities.concat(bravoEntities);
}

/**
 * Polyfill-like helper to execute regex multiple times against a string.
 * Used to extract multiple regex groups (useful for Nashorn JS environments without String.prototype.matchAll).
 */
function matchAll(regex, str) {
  var matches = [];
  var match;
  while ((match = regex.exec(str)) !== null) {
    matches.push(match);
  }
  return matches;
}

/**
 * Parses a string containing multiple PEM blocks and returns an array of individual PEM certificate strings.
 */
function extractIndividualCertificatesFromPemString(pemString) {
  var pemRegex = /-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9\s/+=\n\r]+?)\s*-----END CERTIFICATE-----/g;
  var matches = matchAll(pemRegex, pemString);
  var result = [];

  for (var match of matches) {
    result.push(`-----BEGIN CERTIFICATE-----\n${match[1].trim()}\n-----END CERTIFICATE-----`);
  }

  return result;
}

/**
 * Uses native Java classes to parse a PEM string and extract certificate attributes
 * like Subject, Issuer, NotBefore, NotAfter, and Serial Number.
 */
function getCertificateAttributes(pemCert) {
  log.debug('parsing certificate to get attributes');
  try {
    var certFactory = java.security.cert.CertificateFactory.getInstance('X.509');
    var certStream = new java.io.ByteArrayInputStream(new java.lang.String(pemCert).getBytes());
    var cert = certFactory.generateCertificate(certStream);
    var certData = {
      subject: cert.getSubjectDN().getName(),
      issuer: cert.getIssuerDN().getName(),
      notBefore: cert.getNotBefore(),
      serial: cert.getSerialNumber().toString(),
      notAfter: cert.getNotAfter()
    };
    log.debug('parsed cert data: {}', certData);
    return certData;
  } catch (e) {
    log.error('ERROR parsing certificate: ' + e);
    return null;
  }
}

/**
 * Utility to fetch multiple ESV secret values directly by their property names.
 */
function getEsvSecretValues(secrets) {
  var vals = [];
  for (var s of secrets) {
    // ESVs are fetched by converting hyphens back to dots as property keys
    var val = identityServer.getProperty(s.replace(/-/g, '.'));
    if (val && val.indexOf('-----BEGIN CERTIFICATE-----') !== -1) vals.push({ name: s, value: val, expiry: null, status: 0 });
  }
  return vals;
}

/**
 * Retrieves the deep configuration data for a specific SAML entity (e.g., IDP or SP configuration).
 */
function getSamlEntityConfigurationData(entity, token) {
  try {
    var params = {
      url: `https://${config.envFqdn}/am/json/realms/root/realms/alpha/realm-config/saml2/${entity.location}/${entity._id}`,
      method: 'GET',
      authenticate: {
        type: 'bearer',
        token: token
      }
    };
    var entityRet = openidm.action('external/rest', 'call', params);
    return entityRet || null;
  } catch (e) {
    log.error('Error getting configuration data for entity {}: {}', entity.entityId, e);
    return null;
  }
}

/**
 * Exports the raw XML metadata for a specific SAML entity ID.
 */
function getSamlEntityMetadata(entityId, token) {
  try {
    var params = {
      url: `https://${config.envFqdn}/am/ExportSamlMetadata?entityid=${entityId}&realm=/alpha`,
      method: 'GET',
      authenticate: {
        type: 'bearer',
        token: token
      }
    };
    var metadataRet = openidm.action('external/rest', 'call', params);
    if (metadataRet && metadataRet.body) {
      return metadataRet.body;
    }
    return null;
  } catch (e) {
    log.error('Error getting metadata for entity {}: {}', entityId, e);
    return null;
  }
}

/**
 * Parses raw SAML XML metadata to find and extract all X509Certificates embedded within KeyDescriptors.
 */
function parseSamlMetadataXml(metadataXml) {
  var factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
  factory.setNamespaceAware(true);
  var builder = factory.newDocumentBuilder();
  var xmlInput = new org.xml.sax.InputSource(new java.io.StringReader(metadataXml));
  var doc = builder.parse(xmlInput);
  var certs = [];

  // Find all KeyDescriptors
  var keyDescriptors = doc.getElementsByTagNameNS('*', 'KeyDescriptor');
  for (var i = 0; i < keyDescriptors.getLength(); i++) {
    var keyDescriptor = keyDescriptors.item(i);
    var use = keyDescriptor.getAttribute('use'); // Indicates 'signing' or 'encryption'
    var certNodes = keyDescriptor.getElementsByTagNameNS('*', 'X509Certificate');

    // Extract base64 cert string and format as PEM
    for (var j = 0; j < certNodes.getLength(); j++) {
      var certNode = certNodes.item(j);
      var certText = certNode.getTextContent();
      var pemCert = '-----BEGIN CERTIFICATE-----\n' + certText.match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----';
      certs.push({ use: use, pem: pemCert });
    }
  }
  return certs;
}

/**
 * Retrieves a paginated list of all ESV secrets from the environment API.
 */
function getEsvSecretList(token) {
  var params = {
    url: `https://${config.envFqdn}/environment/secrets?_pagedResultsOffset=0&_pageSize=100&_sortKeys=_id`,
    method: 'GET',
    authenticate: {
      type: 'bearer',
      token: token
    }
  };
  var esvRet = openidm.action('external/rest', 'call', params);

  if (esvRet.resultCount > 0) {
    var esvIds = esvRet.result.map((s) => s._id.replace(/-/g, '.')); // convert secret ids to property format
    log.debug('esvIds {}', esvIds);
    return esvIds;
  }
  return [];
}

/**
 * Main Execution Block (IIFE - Immediately Invoked Function Expression)
 * Coordinates the fetching of secrets, checking cert expiry, matching to SAML entities, and triggering notifications.
 */
(function () {
  log.info('start >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>');
  var now = Date.now();
  resolveConfigObject(); // Load and resolve configuration from ESV at the start of the script

  // Step 1: Obtain Bearer Token
  var bearerToken = getAccessToken();
  if (bearerToken == null) {
    log.error('Could not obtain bearer token, cannot continue with certificate expiry analysis');
    return {
      status: 'error',
      message: 'Could not obtain bearer token, cannot continue with certificate expiry analysis'
    };
  }

  // Step 2: Get all mappings of logical Secret IDs -> ESVs
  var sidMapping = getAllSecretIdToEsvMappings(bearerToken);

  var allSamlCerts = {}; // List to hold all certs found in SAML metadata for reporting purposes
  var reportableCertsFound = false;

  var samlEntities = getAllSamlEntities(bearerToken);
  log.info('found {} saml entities', samlEntities.length);
  for (var e of samlEntities) {
    var entityData = getSamlEntityConfigurationData(e, bearerToken);
    log.debug('saml entity: {}', e);

    var metadata = getSamlEntityMetadata(e.entityId, bearerToken);
    if (!metadata) {
      log.debug('No metadata found for entity {}, skipping cert mapping for this entity', e.entityId);
      continue;
    }
    var metadataCerts = parseSamlMetadataXml(metadata);
    var certData = null;
    log.info('found {} certs in metadata for entity {}', metadataCerts.length, e.entityId);

    for (var mc of metadataCerts) {
      certData = getCertificateAttributes(mc.pem);
      if (
        typeof entityData[e.roles[0]].assertionContent.signingAndEncryption.secretIdAndAlgorithms.secretIdIdentifier !== 'undefined' && 
        entityData[e.roles[0]].assertionContent.signingAndEncryption.secretIdAndAlgorithms.secretIdIdentifier) {
        var entitySecretId = entityData[e.roles[0]].assertionContent.signingAndEncryption.secretIdAndAlgorithms.secretIdIdentifier;
        certData.esvs = {};
        if (sidMapping[`am.applications.federation.entity.providers.saml2.${entitySecretId}.signing`]) 
          certData.esvs[sidMapping[`am.applications.federation.entity.providers.saml2.${entitySecretId}.signing`]] = true;
        if (sidMapping[`am.applications.federation.entity.providers.saml2.${entitySecretId}.encryption`]) 
          certData.esvs[sidMapping[`am.applications.federation.entity.providers.saml2.${entitySecretId}.encryption`]] = true;
        if (sidMapping[`am.applications.federation.entity.providers.saml2.${entitySecretId}.mtls`]) 
          certData.esvs[sidMapping[`am.applications.federation.entity.providers.saml2.${entitySecretId}.mtls`]] = true;
      }
      if (certData.notAfter.getTime() - now < config.warningDays * 24 * 60 * 60 * 1000) {
        if (certData.notAfter.getTime() < now) {
          certData.status = -1; // expired
          reportableCertsFound = true;
          log.warn('cert "{}" expired on {}', certData.subject, certData.notAfter);
        } else {
          certData.status = Math.round((certData.notAfter.getTime() - now) / (1000 * 60 * 60 * 24)); // days until expiry
          reportableCertsFound = true;
          log.warn('cert "{}" expiring on {}', certData.subject, certData.notAfter);
        }
      } else {
        certData.status = 0; // ok
        log.info('cert "{}": cert OK', certData.subject);
      }

      certData.samlEntity = [{ id: `${e.entityId}`, use: `${mc.use}`, type: `SAML ${e.location} ${e.roles[0]}` }];
      if (allSamlCerts[`${certData.subject}|${certData.issuer}|${certData.serial}`]) {
        log.info('Found duplicate cert for subject {} and issuer {}, appending entity {} to existing entry', certData.subject, certData.issuer, certData.samlEntity);
        var existingCert = allSamlCerts[`${certData.subject}|${certData.issuer}|${certData.serial}`];
        existingCert.samlEntity.push({ id: `${e.entityId}`, use: `${mc.use}`, type: `SAML ${e.location} ${e.roles[0]}` }); // append entity to existing cert entry for reporting
      } else {
        log.info('Adding cert with subject {} and issuer {} for entity {} to allSamlCerts', certData.subject, certData.issuer, certData.samlEntity);
        allSamlCerts[`${certData.subject}|${certData.issuer}|${certData.serial}`] = certData;
      }
    }
  }
  log.warn('certs found in SAML metadata for all entities: {}', Object.keys(allSamlCerts).length);

  // Step 5: Send notification if criteria are met

  if (reportableCertsFound || !config.onlySendEmailIfActionNeeded) {
    sendNotificationEmail(allSamlCerts);
  } else {
    log.info('No reportable certs found and onlySendEmailIfActionNeeded is true, skipping sending notification email');
  }

  log.info('end <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<');

  // Return the evaluation context
  return {
    status: 'done',
    result: allSamlCerts
  };
})();
