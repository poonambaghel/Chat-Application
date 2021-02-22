package com.poonam.ChatApp.service;

import org.mybatis.logging.Logger;
import org.mybatis.logging.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.function.Supplier;

@Component
public class HashService {
    private Logger logger = LoggerFactory.getLogger(HashService.class);

    public String getHashedValue(String data, String salt) {
        byte[] hashedValue = null;

        KeySpec spec = new PBEKeySpec(data.toCharArray(), salt.getBytes(), 5000, 128);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            hashedValue = factory.generateSecret(spec).getEncoded();
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            //Supplier<String> msg=e.getMessage();
            Supplier<String> s = () -> e.getMessage();
            logger.error(s);
        }

        return Base64.getEncoder().encodeToString(hashedValue);
    }
}