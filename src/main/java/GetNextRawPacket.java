
/* interfaz 2*/
import com.sun.jna.Platform;
import java.io.IOException;
import java.net.Inet4Address;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import javax.swing.JOptionPane;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class GetNextRawPacket {
    private static final String[] MENU = { "Captura de paquetes al vuelo", "Captura de paquetes desde un archivo", };

    private static final String[] TYPE = { "ARP", "IP" };

    private static final String PCAP_FILE_KEY = GetNextRawPacket.class.getName() + ".pcapFile";

    private static final String COUNT_KEY = GetNextRawPacket.class.getName() + ".count";

    private static final String READ_TIMEOUT_KEY = GetNextRawPacket.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = GetNextRawPacket.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    private static final String BUFFER_SIZE_KEY = GetNextRawPacket.class.getName() + ".bufferSize";
    private static final int BUFFER_SIZE = Integer.getInteger(BUFFER_SIZE_KEY, 1 * 1024 * 1024); // [bytes]

    private static final String NIF_NAME_KEY = GetNextRawPacket.class.getName() + ".nifName";
    private static final String NIF_NAME = System.getProperty(NIF_NAME_KEY);

    public static void main(String[] args) throws PcapNativeException, NotOpenException, IllegalRawDataException {
        Scanner scanner = new Scanner(System.in);
        PcapHandle handle = null;
        String optionToGet, filtro;
        int numberWeft = 0;

        // Muestra ventana para escoger la forma en como se obtienen los paquetes
        optionToGet = (String) JOptionPane.showInputDialog(null, "Opciones disponibles", "Analizador de paquetes",
                JOptionPane.QUESTION_MESSAGE, null, MENU, MENU[0]);

        // Muestra ventana para obtener el número de tramas a obtener
        try {
            numberWeft = Integer.parseInt(JOptionPane.showInputDialog(null,
                    "Ingresa el numero de tramas a ser capturada", optionToGet, JOptionPane.QUESTION_MESSAGE));
        } catch (NumberFormatException e) {
            System.exit(0);
        }

        /* Carga un archivo .pcap */
        if (optionToGet.equals("Captura de paquetes desde un archivo")) {
            // Muestra ventana para obtener el nombre del archivo
            String PCAP_FILE = null;
            try {
                PCAP_FILE = System.getProperty(PCAP_FILE_KEY, (String) JOptionPane.showInputDialog(null,
                        "Ingresa el nombre de tu archivo con el formato: \n                     nombreArchivo.pcap",
                        optionToGet, JOptionPane.QUESTION_MESSAGE));
            } catch (NumberFormatException e) {
                System.exit(0);
            }

            // Abrimos el archivo de tramas
            try {
                handle = Pcaps.openOffline(PCAP_FILE, TimestampPrecision.NANO);
            } catch (PcapNativeException e) {
                handle = Pcaps.openOffline(PCAP_FILE);
            }
            /* Captura tramas al vuelo */
        } else if (optionToGet.equals("Captura de paquetes al vuelo")) {
            JOptionPane.showConfirmDialog(null,
                    "A continuación se imprimiran en consola las tarjetas de red disponibles", optionToGet,
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            
            System.out.println(COUNT_KEY + ": " + numberWeft);
            System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
            System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
            System.out.println(BUFFER_SIZE_KEY + ": " + BUFFER_SIZE);
            System.out.println(NIF_NAME_KEY + ": " + NIF_NAME); System.out.println("\n");

            /* Seleccionamos la interfaz de red */
            PcapNetworkInterface nif;
            if (NIF_NAME != null) {
                nif = Pcaps.getDevByName(NIF_NAME);
            } else {
                try {
                    nif = new NifSelector().selectNetworkInterface();
                } catch (IOException e) {
                    e.printStackTrace();
                    return;
                }
                if (nif == null) {
                    return;
                }
            }

            System.out.println("");
            for (PcapAddress addr : nif.getAddresses()) {
                if (addr.getAddress() != null) {
                    System.out.println("IP address: " + addr.getAddress());
                }
            }

            // Muestra ventana para obtener el filtro del paquete
            filtro = (String) JOptionPane.showInputDialog(null, "Filtros disponibles", "Analizador de paquetes",
                    JOptionPane.QUESTION_MESSAGE, null, TYPE, TYPE[0]);

            String filter = args.length != 0 ? args[0] : filtro.toLowerCase();
            handle = new PcapHandle.Builder(nif.getName()).snaplen(SNAPLEN).promiscuousMode(PromiscuousMode.PROMISCUOUS)
                    .timeoutMillis(READ_TIMEOUT).bufferSize(BUFFER_SIZE).build();

            handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

            /* Mensaje de impresion de tramas */
            JOptionPane.showConfirmDialog(null,
                    "A continuación se imprimiran en consola " + numberWeft + " tramas de tipo " + filtro, optionToGet,
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        }

        String outFileName = "traza_exportada.cap";
        PcapDumper dumper = handle.dumpOpen(outFileName); // exportamos el archivo

        int num = 0;
        while (true) {
            byte[] packet = handle.getNextRawPacket();

            if (packet == null) {
                continue;
            } else {                 
                dumper.dumpRaw(packet, handle.getTimestamp()); // escribimos en el archivo las tramas

                int tipo_b1 = (packet[12] >= 0) ? packet[12] * 256 : (packet[12] + 256) * 256;
                // Primer byte del campo tipo
                int tipo_b2 = (packet[13] >= 0) ? packet[13] : packet[13] + 256;
                // Segundo byte del campo tipo
                int tipo = tipo_b1 + tipo_b2; // suma binaria
                
                System.out.println("");
                System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

                System.out.print("Campo tipo [" + tipo + "]");

                if (tipo >= 1500) {
                    System.out.println("Trama Ethernet");

                    switch (tipo) {
                        case (int) 2054:
                            System.out.println("\nPROTOCOLO ARP");
                            System.out.printf("Tipo de dirección de hardware: ");
                            int type_address = Byte.toUnsignedInt(packet[15]);

                            switch (type_address) {
                                case 1:
                                    System.out.printf("Ethernet [%02x]\n", packet[15]);
                                    break;
                                case 6:
                                    System.out.printf("IEEE 802 Networks [%02x]\n", packet[15]);
                                    break;
                                case 7:
                                    System.out.printf("ARCNET [%02x]\n", packet[15]);
                                    break;
                                case 15:
                                    System.out.printf("Frame Relay [%02x]\n", packet[15]);
                                    break;
                                case 16:
                                    System.out.printf("Asynchronous Transfer Mode (ATM) [%02x]\n", packet[15]);
                                    break;
                                case 17:
                                    System.out.printf("HDLC [%02x]\n", packet[15]);
                                    break;
                                case 18:
                                    System.out.printf("Fibre Channel [%02x]\n", packet[15]);
                                    break;
                                case 19:
                                    System.out.printf("Asynchronous Transfer Mode (ATM) [%02x]\n", packet[15]);
                                    break;
                                case 20:
                                    System.out.printf("Serial Line [%02x]\n", packet[15]);
                                    break;
                            }

                            System.out.printf("Tipo de protocolo de red (IPv4): %02X %02X\n\n", packet[16], packet[17]);
                            System.out.println(
                                    "Longitud de la direccion de hardware (HLEN): " + Byte.toUnsignedInt(packet[18]));
                            System.out.println(
                                    "Longitud de la direccion de protocolo (PLEN): " + Byte.toUnsignedInt(packet[19]));

                            int op_code = Byte.toUnsignedInt(packet[21]);
                            switch (op_code) {
                                case 1:
                                    System.out.printf("Solicitud ARP: %02x\n", packet[21]);
                                    break;
                                case 2:
                                    System.out.printf("Respuesta ARP: %02x\n", packet[21]);
                                    break;
                                case 3:
                                    System.out.printf("Solicitud RARR: %02x\n", packet[21]);
                                    break;
                                case 4:
                                    System.out.printf("Respuesta RARP: %02x\n", packet[21]);
                                    break;
                            }

                            System.out.printf("Dirección MAC del remitente:%02X:%02X:%02X:%02X:%02X:%02X\n", packet[22],
                                    packet[23], packet[24], packet[25], packet[26], packet[27]);

                            System.out.printf("Dirección IP del remitente: %02X.%02X.%02X.%02X\n", packet[28],
                                    packet[29], packet[30], packet[31]);

                            System.out.printf("Dirección MAC del destinatario:%02X:%02X:%02X:%02X:%02X:%02X\n",
                                    packet[32], packet[33], packet[34], packet[35], packet[36], packet[37]);

                            System.out.printf("Dirección IP del destinatario: %02X.%02X.%02X.%02X\n", packet[38],
                                    packet[39], packet[40], packet[41]);

                            break;

                        case (int) 2048:

                            System.out.println("Protocolo IP.");
                            int ihl = (packet[14] & 0x0f) * 4;
                            System.out.println("Tamaño protocolo IP: " + ihl + " bytes.");
                            byte[] tmp_ip = Arrays.copyOfRange(packet, 14, 14 + ihl);
                            IpV4Packet ip = IpV4Packet.newPacket(tmp_ip, 0, tmp_ip.length);
                            System.out.println("Versión: IpV" + ip.getHeader().getVersion().valueAsString() + ". \n");
                            System.out.println(
                                    "Longitud de la cabecera: " + (ip.getHeader().getIhlAsInt() * 32) + " bits.");
                            System.out.println("Servicios diferenciados: " + ip.getHeader().getTos().toString());
                            int lt = (ip.getHeader().getTotalLength() > 0) ? ip.getHeader().getTotalLength()
                                    : ip.getHeader().getTotalLength() + 65536;
                            System.out.println("Longitud total [PDU + datos utiles]: " + lt);
                            int id = (ip.getHeader().getIdentification() > 0) ? ip.getHeader().getIdentification()
                                    : ip.getHeader().getIdentification() + 65536;
                            System.out.println("Identificador: " + id);
                            String df = (ip.getHeader().getDontFragmentFlag()) ? "Encendida" : "Apagada";
                            String mf = (ip.getHeader().getMoreFragmentFlag()) ? "Más fragmentos" : "Último fragmento";
                            System.out.println("Bandera.\nEstado: " + df + "\nFragmentación: " + mf);
                            short fo = (ip.getHeader().getFragmentOffset());
                            System.out.println("Desplazamiento del fragmento: " + fo);
                            int ttl = (ip.getHeader().getTtlAsInt());
                            System.out.println("Tiempo de vida: " + ttl);
                            String protocolo = (ip.getHeader().getProtocol().name());
                            System.out.println("Protocolo: " + protocolo);
                            short check_sum = (ip.getHeader().getHeaderChecksum());
                            System.out.println("Suma de verificación de la cabecera: " + check_sum);
                            String source = (ip.getHeader().getSrcAddr().getHostAddress());
                            System.out.println("Dirección IP origen: " + source);
                            String destination = (ip.getHeader().getDstAddr().getHostAddress());
                            System.out.println("Dirección IP destino: " + destination);
                            List<IpV4Packet.IpV4Option> option = ip.getHeader().getOptions();
                            System.out.println("Optiones [" + option.size() + "]: " + option);
                            for (byte i = 0; i < option.size(); i++) {
                                System.out.println(option.get(i).getType());
                            }
                            break;
                        default:
                            System.out.println("Not identified");
                    }
                } else {
                    System.out.println("\nTrama IEEE802.3");
                    System.out.println("Longitud de la trama: " + tipo + " bytes");

                    int i_g = packet[14] & 0x01;
                    int c_r = packet[15] & 0x01;
                    if (i_g == 0)
                        System.out.println("Destinatario Individual");
                    else
                        System.out.println("Destinatario Grupal");
                    if (c_r == 0)
                        System.out.println("Comando");
                    else
                        System.out.println("Acuse");

                    System.out.println("");
                    if ((packet[16] & 0x01) == 0) {
                        System.out.println("Trama tipo I");
                        if (tipo > 3) {
                            System.out.println("Formato Extendido (2 bytes de campo de control): "
                                    + convertirDecimalABinarioLongitud(packet[16], 8) + " "
                                    + convertirDecimalABinarioLongitud(packet[17], 8));
                            int ns = (packet[16] >> 1) & 0x7f;
                            System.out.println("Numero de secuencia de trama enviado N(S) (7 bits): "
                                    + convertirDecimalABinarioLongitud(ns, 7) + ", Decimal: " + ns);
                            System.out.println("No. secuencia de la proxima trama esperada N(R) (7 bits): "
                                    + convertirDecimalABinarioLongitud((packet[17] >> 1) & 0x7f, 7) + ", Decimal: "
                                    + ((packet[17] >> 1) & 0x7f));
                            System.out.println("Put/Final: " + (packet[17] & 0x01));
                        } else {
                            System.out.println("Formato Normal (1 byte de campo de control): "
                                    + convertirDecimalABinarioLongitud(packet[16], 8));
                            int ns = (packet[16] >> 5) & 0x07;
                            System.out.println("Numero de secuencia de trama enviado N(S) (3 bits): "
                                    + convertirDecimalABinarioLongitud(ns, 3) + ", Decimal: " + ns);
                            System.out.println("No. secuencia de la proxima trama esperada N(R) (3 bits): "
                                    + convertirDecimalABinarioLongitud((packet[16] >> 2) & 0x03, 3) + ", Decimal: "
                                    + ((packet[16] >> 2) & 0x03));
                            System.out.println("Put/Final: " + ((packet[16] >> 4) & 0x01));
                        }
                    } else {
                        if (((packet[16] >> 1) & 0x01) == 0) {
                            System.out.println("Trama tipo S");
                            if (tipo > 3) {
                                System.out.println("Formato Extendido (2 bytes de campo de control): "
                                        + convertirDecimalABinarioLongitud(packet[16], 8) + " "
                                        + convertirDecimalABinarioLongitud(packet[17], 8));
                                int codigo = (packet[16] >> 2) & 0x03;
                                System.out.print("Codigo de trama de supervision ");
                                switch (codigo) {
                                    case 0:
                                        System.out.println("00: Listo para recibir");
                                        break;
                                    case 1:
                                        System.out.println("01: Rechazo (REJ)");
                                        break;
                                    case 2:
                                        System.out.println("10: Receptor no listo para recibir");
                                        break;
                                    case 3:
                                        System.out.println("11: Rechazo Selectivo");
                                        break;
                                }
                                System.out.println("No. secuencia de la proxima trama esperada N(R) (7 bits): "
                                        + convertirDecimalABinarioLongitud((packet[17] >> 1) & 0x7f, 7) + ", Decimal: "
                                        + ((packet[17] >> 1) & 0x7f));
                                System.out.println("Put/Final: " + (packet[17] & 0x01));
                            } else {
                                System.out.println("Formato Normal (1 byte de campo de control): "
                                        + convertirDecimalABinarioLongitud(packet[16], 8));
                                int codigo = (packet[16] >> 2) & 0x03;
                                System.out.print("Codigo de trama de supervision ");
                                switch (codigo) {
                                    case 0:
                                        System.out.println("00: Listo para recibir");
                                        break;
                                    case 1:
                                        System.out.println("01: Rechazo (REJ)");
                                        break;
                                    case 2:
                                        System.out.println("10: Receptor no listo para recibir");
                                        break;
                                    case 3:
                                        System.out.println("11: Rechazo Selectivo");
                                        break;
                                }
                                int nr = (packet[16] >> 5) & 0x07;
                                System.out.println("No. secuencia de la proxima trama esperada N(R) (7 bits): "
                                        + convertirDecimalABinarioLongitud(nr, 7) + ", Decimal: " + nr);
                                System.out.println("Put/Final: " + ((packet[16] >> 4) & 0x01));
                            }
                        } else {
                            System.out.println("Trama tipo U");
                            System.out.println("Formato Normal (1 byte de campo de control): "
                                    + convertirDecimalABinarioLongitud(packet[16], 8));
                            int bit1 = (((packet[16] >> 2) & 0x01) * 16);
                            int bit2 = (((packet[16] >> 3) & 0x01) * 8);
                            int bit3 = (((packet[16] >> 5) & 0x01) * 4);
                            int bit4 = (((packet[16] >> 6) & 0x01) * 2);
                            int bit5 = (((packet[16] >> 7) & 0x01) * 1);

                            int codigo = bit1 + bit2 + bit3 + bit4 + bit5;

                            System.out.println("Codigo de trama sin numerar (decimal): " + codigo);
                            switch (codigo) {
                                case 0:
                                    System.out.println("Comando UI Respuesta UI --> Informacion sin numerar: "
                                            + convertirDecimalABinarioLongitud(codigo, 5));
                                    break;
                                case 1:
                                    System.out.println("Comando SNRM --> Activacion de modo de respuesta normal: "
                                            + convertirDecimalABinarioLongitud(codigo, 5));
                                    break;
                                case 2:
                                    System.out.println(
                                            "Comando DISC Respuesta RD --> Desconexion o peticion de desconexion: "
                                                    + convertirDecimalABinarioLongitud(codigo, 5));
                                    break;
                                case 4:
                                    System.out.println("Comando UP --> Muestra sin numerar: "
                                            + convertirDecimalABinarioLongitud(codigo, 5));
                                    break;
                                case 6:
                                    System.out.println("Respuesta UA --> Reconocimiento sin numerar: "
                                            + convertirDecimalABinarioLongitud(codigo, 5));
                                    break;
                                case 16:
                                    System.out.println("Comando SIM Respuesta RIM --> Modo de peticion de informacion: "
                                            + convertirDecimalABinarioLongitud(codigo, 5));
                                    break;
                                case 17:
                                    System.out.println("Comando FRMR Respuesta FRMR --> Rechazo de trama: "
                                            + convertirDecimalABinarioLongitud(codigo, 5));
                                    break;
                                case 25:
                                    System.out.println(
                                            "Comando RSET --> Reset: " + convertirDecimalABinarioLongitud(codigo, 5));
                                    break;
                                case 27:
                                    System.out.println(
                                            "Comando SNRME  --> Activacion de modo de respuesta normal(ampliado): "
                                                    + convertirDecimalABinarioLongitud(codigo, 5));
                                    break;
                                case 28:
                                    System.out.println(
                                            "Comando SABM Respuesta DM --> Activacion de modo de respuesta asincrona balanceada: "
                                                    + convertirDecimalABinarioLongitud(codigo, 5));
                                    break;
                                case 29:
                                    System.out.println("Comando XID Respuesta XID --> Intercambio de ID: "
                                            + convertirDecimalABinarioLongitud(codigo, 5));
                                    break;
                                case 30:
                                    System.out.println(
                                            "Comando SABME  --> Activacion de modo de respuesta asincrona balanceada(ampliado): "
                                                    + convertirDecimalABinarioLongitud(codigo, 5));
                                    break;
                                default:
                                    System.out.println("No hay comando de control o repuesta");
                                    break;
                            }
                            System.out.println("Put/Final: " + ((packet[16] >> 4) & 0x01));
                        }
                    }
                }

                System.out.println(handle.getTimestamp());
                
                for (int j = 0; j < packet.length; j++) {
                    System.out.printf("%02X ", packet[j]);
                    if (j % 16 == 0) {
                        System.out.println("");
                    }
                }
                System.out.println("");
                num++;
                if (num >= numberWeft) {
                    break;
                }
            }
        }
        if (optionToGet.equals("Captura de paquetes al vuelo")) {
            PcapStat ps = handle.getStats();
            System.out.println("ps_recv: " + ps.getNumPacketsReceived());
            System.out.println("ps_drop: " + ps.getNumPacketsDropped());
            System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
            if (Platform.isWindows()) {
                System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
            }
        }
        dumper.close();
        handle.close();
        JOptionPane.showConfirmDialog(null, "Las tramas anteriores han sido exportada al archivo traza_exportada.cap",
                optionToGet, JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
    }

    public static String convertirDecimalABinarioLongitud(long decimal, int n) {
        StringBuilder binario = new StringBuilder();
        while (decimal > 0) {
            short residuo = (short) (decimal % 2);
            decimal = decimal / 2;
            // Insertar el dígito al inicio de la cadena
            binario.insert(0, String.valueOf(residuo));
        }
        while ((binario.length() != n))
            binario.insert(0, "0");
        return binario.toString();
    }
}
