import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

public class ClienteUDP {
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static DatagramSocket socket;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        socket = new DatagramSocket();
        KeyPair keyPair = generarParClaves();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        enviarClavePublica(publicKey);

        Thread enviarThread = new Thread(() -> {
            while (true) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                String mensaje = null;
                try {
                    mensaje = reader.readLine();
                    if (mensaje.equals("salir")) {
                        byte[] bytes = mensaje.getBytes();
                        DatagramPacket packet = new DatagramPacket(bytes, bytes.length, InetAddress.getLocalHost(), 999);
                        socket.send(packet);
                        System.out.println("Desconectado");
                        System.exit(0);
                    } else {
                        byte[] bytes = mensaje.getBytes();
                        DatagramPacket packet = new DatagramPacket(bytes, bytes.length, InetAddress.getLocalHost(), 999);
                        socket.send(packet);
                        System.out.println("Enviado");
                    }
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            }
        });

        Thread recibirThread = new Thread(() -> {
            while (true) {
                byte[] recibido = new byte[1024];
                DatagramPacket paqueteRecibido = new DatagramPacket(recibido, recibido.length);
                try {
                    socket.receive(paqueteRecibido);
                    String paqueteRecibidoString = new String(paqueteRecibido.getData(), 0, paqueteRecibido.getLength());
                    String desencriptado = desencriptarMensaje(paqueteRecibidoString);
                    System.out.println("Cliente conectado: "+paqueteRecibido.getSocketAddress() + ":");
                    System.out.println("Fecha de envio: "+LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_TIME));
                    System.out.println(desencriptado);
                } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException |
                         IllegalBlockSizeException | BadPaddingException | IOException e) {
                    throw new RuntimeException(e);
                }
            }
        });

        recibirThread.start();
        enviarThread.start();
    }

    private static String desencriptarMensaje(String paqueteRecibidoString) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] desencriptado = cipher.doFinal(Base64.getDecoder().decode(paqueteRecibidoString));
        return new String(desencriptado);
    }

    private static void enviarClavePublica(PublicKey clavePublica) throws IOException {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteOut);
        objectOutputStream.writeObject(clavePublica);
        byte[] bytesPublica = byteOut.toByteArray();
        DatagramPacket publicData = new DatagramPacket(bytesPublica, bytesPublica.length, InetAddress.getLocalHost(), 999);
        socket.send(publicData);
    }

    private static KeyPair generarParClaves() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}
