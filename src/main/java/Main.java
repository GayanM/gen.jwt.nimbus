import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Properties;

/**
 * Created by gayan on 3/18/18.
 */
public class Main {

    private String getJTI() {
        return Integer.toString((int)(Math.random()*10000));
    }

    private Properties getProperties(String fileName) throws IOException {

        Properties prop = new Properties();
        ClassLoader classLoader = getClass().getClassLoader();
        prop.load(classLoader.getResourceAsStream(fileName));
        return prop;

    }

    private FileInputStream getFile(String fileName) throws IOException {

        ClassLoader classLoader = this.getClass().getClassLoader();

        Path temp = Files.createTempFile("resource-", ".jks");
        Files.copy(classLoader.getResourceAsStream(fileName), temp, StandardCopyOption.REPLACE_EXISTING);
        return new FileInputStream(temp.toFile());

    }

    public static void main (String args[]) throws ParseException, IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, JOSEException {

        Main main = new Main();
        Properties properties = main.getProperties("config.properties");

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("iss", properties.getProperty("iss"));
        jsonObject.put("sub", properties.getProperty("iss"));
        jsonObject.put("aud", properties.getProperty("aud"));
        jsonObject.put("jti", main.getJTI());
        jsonObject.put("exp", Calendar.getInstance().getTimeInMillis() + Long.parseLong(properties.
                getProperty("liftTimeInSec"))*1000);
        jsonObject.put("iat", Calendar.getInstance().getTimeInMillis());

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(main.getFile(properties.getProperty("keystore")), properties.getProperty("keystorePass").
                toCharArray());
        PrivateKey privateKey = (PrivateKey)keystore.getKey(properties.getProperty("alias"), properties.
                getProperty("keyPass").toCharArray());

        JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);
        JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(jsonObject);
        SignedJWT signedJWT = new SignedJWT(header, jwtClaimsSet);
        signedJWT.sign(signer);
        System.out.println(signedJWT.serialize());
    }
}
