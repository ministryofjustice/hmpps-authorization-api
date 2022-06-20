package uk.gov.justice.digital.hmpps.hmppsauthorizationserver.service;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPublicKeySpec;


/**
 * Code replicated from org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory, within the now deprecated spring-security-oauth2 library
 *
 * TODO - investigate replacement
 */

public class KeyStoreKeyFactory {

    private static final Log logger = LogFactory.getLog(KeyStoreKeyFactory.class);

    private final Resource resource;

    private final char[] password;

    private KeyStore store;

    private Object lock = new Object();

    public KeyStoreKeyFactory(Resource resource, char[] password) {
        this.resource = resource;
        this.password = password;
    }

    public KeyPair getKeyPair(String alias) {
        return getKeyPair(alias, password);
    }

    public KeyPair getKeyPair(String alias, char[] password) {
        InputStream inputStream = null;
        try {
            synchronized (lock) {
                if (store == null) {
                    synchronized (lock) {
                        store = KeyStore.getInstance("jks");
                        inputStream = resource.getInputStream();
                        store.load(inputStream, this.password);
                    }
                }
            }
            RSAPrivateCrtKey key = (RSAPrivateCrtKey) store.getKey(alias, password);
            RSAPublicKeySpec spec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
            return new KeyPair(publicKey, key);
        }
        catch (Exception e) {
            throw new IllegalStateException("Cannot load keys from store: " + resource, e);
        }
        finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            }
            catch (IOException e) {
                logger.warn("Cannot close open stream: ", e);
            }
        }
    }
}
