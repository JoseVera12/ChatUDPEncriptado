import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.concurrent.locks.ReentrantLock;

public class ServidorUDP {
    private static Map<String, SocketAddress> clientesConectados;
    private static Map<SocketAddress, PublicKey> clavesClientes;
    private static DatagramSocket servidor;
    private static ReentrantLock lock;
    private static ArrayList<String> nombresDisponibles = new ArrayList<>();
    private static int contador = 0;

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        clavesClientes = new HashMap<>();
        lock = new ReentrantLock();
        nombresDisponibles.add("Antonio");
        nombresDisponibles.add("Inma");
        nombresDisponibles.add("Ernesto");
        nombresDisponibles.add("Sergio");
        nombresDisponibles.add("David");
        clientesConectados = new HashMap<>();

        Thread mensajesThread = new Thread(() -> {
            try {
                servidor = new DatagramSocket(999);
            } catch (SocketException e) {
                throw new RuntimeException(e);
            }
            while (true) {
                String nombreUsuario;
                byte[] mensaje = new byte[1024];
                DatagramPacket paquete = new DatagramPacket(mensaje, mensaje.length);
                try {
                    servidor.receive(paquete);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                lock.lock();
                String paqueteString = new String(paquete.getData(), 0, paquete.getLength());
                if (paqueteString.equals("salir")) {
                    desconectarCliente(paquete.getSocketAddress());
                } else {
                    SocketAddress direccionCliente = paquete.getSocketAddress();
                    if (clienteExiste(direccionCliente)) {
                        nombreUsuario = obtenerNombreUsuario(direccionCliente);
                        clientesConectados.forEach((cliente, socket) -> {
                            String encrypted = encriptarMensaje(paqueteString, socket);
                            try {
                                if (!nombreUsuario.equals(cliente)) {
                                    reenviarMensajes(encrypted, nombreUsuario, socket);
                                }
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        });
                    } else {
                        ByteArrayInputStream inputStream = new ByteArrayInputStream(paquete.getData());
                        ObjectInputStream objectInputStream = null;
                        try {
                            objectInputStream = new ObjectInputStream(inputStream);
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                        PublicKey clavePublica = null;
                        try {
                            clavePublica = (PublicKey) objectInputStream.readObject();
                        } catch (IOException | ClassNotFoundException e) {
                            throw new RuntimeException(e);
                        }
                        clavesClientes.put(direccionCliente, clavePublica);
                        nombreUsuario = obtenerNombre();
                        clientesConectados.put(nombreUsuario, direccionCliente);
                    }
                    System.out.println("Mensaje nuevo de: " + nombreUsuario);
                    lock.unlock();
                }
            }
        });
        mensajesThread.start();
    }

    private static String encriptarMensaje(String paqueteString, SocketAddress socket) {
        byte[] encrypted;
        PublicKey publicKey = clavesClientes.get(socket);
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encrypted = cipher.doFinal(paqueteString.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static String obtenerNombreUsuario(SocketAddress direccionCliente) {
        AtomicReference<String> nombreUsuario = new AtomicReference<>("usuario");
        clientesConectados.forEach((key, value) -> {
            if (direccionCliente.equals(value)) {
                nombreUsuario.set(key);
            }
        });
        return nombreUsuario.get();
    }

    private static String obtenerNombre() {
        String nombre = "Usuario";
        if (!nombresDisponibles.isEmpty()) {
            nombre = nombresDisponibles.get(contador);
            nombresDisponibles.remove(contador);
        }
        contador++;
        return nombre;
    }

    private static boolean clienteExiste(SocketAddress direccionCliente) {
        AtomicBoolean existe = new AtomicBoolean(false);
        clientesConectados.forEach((key, value) -> {
            if (value.equals(direccionCliente)) {
                existe.set(true);
            }
        });
        return existe.get();
    }

    private static void reenviarMensajes(String encryptedMessage, String clientName, SocketAddress socket) throws IOException {
        byte[] messageBytes = encryptedMessage.getBytes();
        DatagramPacket packet = new DatagramPacket(messageBytes, messageBytes.length, socket);
        servidor.send(packet);
    }

    public static void desconectarCliente(SocketAddress socketAddress) {
        String senderName = obtenerNombreUsuario(socketAddress);
        String message = senderName + " desconectado.";
        clientesConectados.remove(senderName);
        clientesConectados.forEach((key, value) -> {
            String encrypted = encriptarMensaje(message, value);
            try {
                reenviarMensajes(encrypted, key, value);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }
}
