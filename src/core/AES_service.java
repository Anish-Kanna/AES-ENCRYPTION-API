package core;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class AES_service {
    private static final byte[] magic = {(byte) 0x00, (byte) 0x00, (byte) 0xAB, (byte) 0x64};
    private static final byte version = 0x01;
    private static final byte algorithm = 0x01;

//    private static final int IV_Length = 12;
//    private static final int Salt_Length = 16;
//
//    private static final int PBKDF2_ITERATIONS = 12000;
//    private static final int KEY_LENGTH = 256;

    private static final int GCM_TAG_BITS = 128;


    public static byte[] encrypt(byte[] input_data, String password, String extension) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        //breaking conditions
        if(input_data == null || input_data.length == 0){
            throw new IllegalArgumentException("The input data is null or empty");
        }
        if(password.isEmpty()){
            throw new IOException("Invalid password size");
        }
        if(extension == null || extension.length() > 255){
            throw new IOException("Invalid extension size");
        }

        //IV and SALT random byte generation
        byte[] randombytes_IV = new byte[12];
        byte[] randombytes_salt = new byte[16];

        SecureRandom random = new SecureRandom();

        random.nextBytes(randombytes_IV);
        random.nextBytes(randombytes_salt);

        //key generation
        SecretKey Secret_key = derive_key(password, randombytes_salt);

        //Encryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, randombytes_IV);
        cipher.init(Cipher.ENCRYPT_MODE, Secret_key, spec);




//        byte[] encrypted_bytes = cipher.doFinal(input_data);

        //Container
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] ext_bytes = extension.getBytes(StandardCharsets.UTF_8);
        baos.write(magic);
        baos.write(version);
        baos.write(algorithm);
        baos.write(randombytes_IV);
        baos.write(randombytes_salt);
        baos.write((byte) ext_bytes.length);
        baos.write(ext_bytes);
        InputStream in = new ByteArrayInputStream(input_data);
        byte[] buffer = new byte[16 * 1024];
        int byt;
        while((byt = in.read(buffer)) != -1){
            byte[] cipher_text = cipher.update(buffer, 0, byt);
            if(cipher_text != null){
               baos.write(cipher_text);
            }
        }
        byte[] encrypted_bytes = cipher.doFinal();
        if(encrypted_bytes != null){
            baos.write(encrypted_bytes);
        }
        baos.close();
        return baos.toByteArray();
    }

    public static Decryption_Res decrypt(byte[] encrypted_data, String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

        if(password == null || password.isEmpty()){
            throw new SecurityException("Authentication failed (wrong password or Tampered file");
        }
        if(encrypted_data.length < 35){
            throw new IOException("Invalid header");
        }

        for (int i = 0; i < 4; i++) {
            if (encrypted_data[i] != magic[i]) {
                throw new IOException("Invalid magic bytes");
            }
        }

        if (encrypted_data[4] != version) {
            throw new IOException("Unsupported version");
        }

        if (encrypted_data[5] != algorithm) {
            throw new IOException("Unsupported algorithm ID");
        }

        int ext_len = encrypted_data[34] & 0xFF;
        int total_header_len = ext_len + 35;

        if(encrypted_data.length < total_header_len){
            throw new IOException("Invalid header");
        }

        byte[] IV =  new byte[12];
        System.arraycopy(encrypted_data, 6, IV, 0, 12);

        byte[] salt = new byte[16];
        System.arraycopy(encrypted_data, 18, salt, 0, 16);

        byte[] ext_bytes = new byte[ext_len];
        System.arraycopy(encrypted_data, 35, ext_bytes, 0, ext_len);

        String ext_string = new String(ext_bytes, StandardCharsets.UTF_8);

        int cipher_text_len = encrypted_data.length - total_header_len;
        //int cipher_start = total_header_len;
        byte[] cipherText = new byte[cipher_text_len];

        System.arraycopy(encrypted_data, total_header_len, cipherText, 0, cipherText.length);
        SecretKey secretkey = derive_key(password, salt);

        GCMParameterSpec gcm = new GCMParameterSpec(GCM_TAG_BITS, IV);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretkey, gcm);

        try {
            InputStream in = new ByteArrayInputStream(cipherText);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[16 * 1024];
            int byt;

            while ((byt = in.read(buffer)) != -1) {
                byte[] decrypted_text = cipher.update(buffer, 0, byt);
                if (decrypted_text != null) {
                    baos.write(decrypted_text);
                }
            }

            byte[] decrypted_bytes = cipher.doFinal();
            if (decrypted_bytes != null) {
                baos.write(decrypted_bytes);
            }
            return new Decryption_Res(baos.toByteArray(), ext_string);
        } catch (AEADBadTagException e) {
            throw new SecurityException("Authentication failed (wrong password or Tampered file");
        }
    }

    public static record Decryption_Res(byte[] plainText, String extension) {
    }


    private static SecretKey derive_key(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final String hash_algo = "PBKDF2withHmacSHA256";
        final int ITERATIONS = 12000;
        final int KEY_LENGTH = 256;

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);

        SecretKeyFactory factory = SecretKeyFactory.getInstance(hash_algo);

        byte[] hash = factory.generateSecret(spec).getEncoded();
        spec.clearPassword();
        return new SecretKeySpec(hash, "AES");
    }

    public static byte[] encoder(byte[] plaintext){
        char[] BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (int i = 0; i < plaintext.length; i += 3) {

            int b1 = plaintext[i] & 0xFF;
            int b2 = (i + 1 < plaintext.length) ? plaintext[i + 1] & 0xFF : 0;
            int b3 = (i + 2 < plaintext.length) ? plaintext[i + 2] & 0xFF : 0;

            int bits = (b1 << 16) | (b2 << 8) | b3;

            bos.write(BASE64[(bits >> 18) & 0x3F]);
            bos.write(BASE64[(bits >> 12) & 0x3F]);

            if (i + 1 < plaintext.length) {
                bos.write(BASE64[(bits >> 6) & 0x3F]);
            } else {
                bos.write('=');
            }

            if (i + 2 < plaintext.length) {
                bos.write(BASE64[bits & 0x3F]);
            } else {
                bos.write('=');
            }
        }
        return bos.toByteArray();
    }

    public static byte[] decoder(byte[] base64Input) {

        int[] BASE64_REVERSE = new int[256];
        String base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        for (int i = 0; i < base64Chars.length(); i++) {
            BASE64_REVERSE[base64Chars.charAt(i)] = i;
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        for (int i = 0; i < base64Input.length; i += 4) {

            int c1 = BASE64_REVERSE[base64Input[i] & 0xFF];
            int c2 = BASE64_REVERSE[base64Input[i + 1] & 0xFF];

            int c3 = base64Input[i + 2] == '=' ? 0 : BASE64_REVERSE[base64Input[i + 2] & 0xFF];
            int c4 = base64Input[i + 3] == '=' ? 0 : BASE64_REVERSE[base64Input[i + 3] & 0xFF];

            int bits = (c1 << 18) | (c2 << 12) | (c3 << 6) | c4;

            bos.write((bits >> 16) & 0xFF);

            if (base64Input[i + 2] != '=') {
                bos.write((bits >> 8) & 0xFF);
            }

            if (base64Input[i + 3] != '=') {
                bos.write(bits & 0xFF);
            }
        }

        return bos.toByteArray();
    }

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        String data = "Time is a flat circle and it has no dimension";
        byte[] input_data = data.getBytes(StandardCharsets.UTF_8);
        String password = "Anish";
        String extension = "txt";
        byte[] cipher_text = encrypt(input_data, password, extension);
        System.out.println(Arrays.toString(cipher_text));
        System.out.println(Arrays.toString(cipher_text).length());

        Decryption_Res p = decrypt(cipher_text, password);
        String pt =  new String(p.plainText, StandardCharsets.UTF_8);
        System.out.println(pt);
        System.out.println(p.extension);
        System.out.println("Plain length = " + p.plainText.length);
    }
}
