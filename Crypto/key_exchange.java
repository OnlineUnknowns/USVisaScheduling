import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class KeyExchange {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public KeyExchange() throws Exception {
        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");

        generator.initialize(4096);

        KeyPair pair =
                generator.generateKeyPair();

        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String encryptMessage(
            String message,
            PublicKey targetKey
    ) throws Exception {

        Cipher cipher =
                Cipher.getInstance("RSA");

        cipher.init(
                Cipher.ENCRYPT_MODE,
                targetKey
        );

        byte[] encrypted =
                cipher.doFinal(
                        message.getBytes()
                );

        return Base64.getEncoder()
                .encodeToString(encrypted);
    }

    public String decryptMessage(
            String encryptedMessage
    ) throws Exception {

        Cipher cipher =
                Cipher.getInstance("RSA");

        cipher.init(
                Cipher.DECRYPT_MODE,
                privateKey
        );

        byte[] decrypted =
                cipher.doFinal(
                        Base64.getDecoder()
                                .decode(encryptedMessage)
                );

        return new String(decrypted);
    }

    public String generateDigitalSignature(
            String message
    ) throws Exception {

        Signature signature =
                Signature.getInstance(
                        "SHA256withRSA"
                );

        signature.initSign(
                privateKey
        );

        signature.update(
                message.getBytes()
        );

        byte[] signed =
                signature.sign();

        return Base64.getEncoder()
                .encodeToString(signed);
    }

    public boolean verifySignature(
            String message,
            String signatureData,
            PublicKey senderKey
    ) throws Exception {

        Signature signature =
                Signature.getInstance(
                        "SHA256withRSA"
                );

        signature.initVerify(
                senderKey
        );

        signature.update(
                message.getBytes()
        );

        return signature.verify(
                Base64.getDecoder()
                        .decode(signatureData)
        );
    }

    public static void main(
            String[] args
    ) throws Exception {

        KeyExchange server =
                new KeyExchange();

        KeyExchange client =
                new KeyExchange();

        String message =
                "Secure military payload";

        String encrypted =
                client.encryptMessage(
                        message,
                        server.getPublicKey()
                );

        String decrypted =
                server.decryptMessage(
                        encrypted
                );

        String signature =
                client.generateDigitalSignature(
                        message
                );

        boolean valid =
                client.verifySignature(
                        message,
                        signature,
                        client.getPublicKey()
                );

        System.out.println(
                "Encrypted: " + encrypted
        );

        System.out.println(
                "Decrypted: " + decrypted
        );

        System.out.println(
                "Valid Signature: " + valid
        );
    }
}