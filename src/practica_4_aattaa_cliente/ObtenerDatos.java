package practica_4_aattaa_cliente;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import javax.smartcardio.*;
import javax.swing.JOptionPane;
import es.gob.jmulticard.jse.provider.DnieProvider;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import static javax.management.Query.lt;
/**
 * La clase ObtenerDatos implementa cuatro métodos públicos que permiten obtener
 * determinados datos de los certificados de tarjetas DNIe, Izenpe y Ona.
 *
 * @author tbc
 */
public class ObtenerDatos {

    private static final byte[] dnie_v_1_0_Atr = {
        (byte) 0x3B, (byte) 0x7F, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x6A, (byte) 0x44,
        (byte) 0x4E, (byte) 0x49, (byte) 0x65, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x90, (byte) 0x00};
    private static final byte[] dnie_v_1_0_Mask = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF};

    public ObtenerDatos() {
    }

    public Usuario LeerNIF() {

        Usuario user = null;
        byte[] datos=null;
        try {
            Card c = ConexionTarjeta();
            if (c == null) {
                throw new Exception("ACCESO DNIe: No se ha encontrado ninguna tarjeta");
            }
            byte[] atr = c.getATR().getBytes();
            CardChannel ch = c.getBasicChannel();

            if (esDNIe(atr)) {
                datos = leerCertificado(ch);
                if(datos!=null)
                    user = leerDatosUsuario(datos);
            }
            c.disconnect(false);

        } catch (Exception ex) {
            Logger.getLogger(ObtenerDatos.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
        return user;
    }

    public byte[] leerCertificado(CardChannel ch) throws CardException, CertificateException {


        int offset = 0;
        String completName = null;

        //[1] PRACTICA 3. Punto 1.a
 
        /**Comando SELECT: 
         * Este comando permite la selección de fichero dedicado (DF) o de un fichero elemental (EF).
         * 
         *   Primer octecto: 0x00 "CLA"
         *   Segundo octecto: 0xA4 "INS"
         *   Tercer octecto: 0x04 "P1" ((DF) Nombre)
         *   Cuarto octecto: 0x00 "P2"
         *   Quinto octecto: 0x0b "LC"  (longitud en bytes)
        */
        
        byte[] command = new byte[]{(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, (byte) 0x4D, (byte) 0x61, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x2E, (byte) 0x46, (byte) 0x69, (byte) 0x6C, (byte) 0x65};
        ResponseAPDU r = ch.transmit(new CommandAPDU(command));
        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        }

        //[2] PRACTICA 3. Punto 1.a 
        
         /** Comando SELECT:
          *
         *  Primer octecto: 0x00 "CLA"
         *  Segundo octecto: 0xA4 "INS"
         *  Tercer octecto: 0x00 "P1" (DF o EF por Id (data field = id))
         *  Cuarto octecto: 0x00 "P2"
         *  Quinto octecto: 0x02 "LC" (longitud en bytes)
         **/
              
        command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x50, (byte) 0x15};
        r = ch.transmit(new CommandAPDU(command));

        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        }

        //[3] PRACTICA 3. Punto 1.a
        
         /** Comando SELECT: 
          * 
         *  Primer octecto: 0x00 "CLA"
         *  Segundo octecto: 0xA4 "INS"
         *  Tercer octecto: 0x00 "P1" (DF o EF por Id (data field = id))
         *  Cuarto octecto: 0x00 "P2"
         *  Quinto octecto: 0x02 "LC" (longitud en bytes)
         **/
        command = new byte[]{(byte) 0x00, (byte) 0xA4, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x60, (byte) 0x04};
        r = ch.transmit(new CommandAPDU(command));

        byte[] responseData = null;
        if ((byte) r.getSW() != (byte) 0x9000) {
            System.out.println("ACCESO DNIe: SW incorrecto");
            return null;
        } else {
            responseData = r.getData();
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] r2 = null;
        int bloque = 0;

        do {
             //[4] PRACTICA 3. Punto 1.b
             /**Los siguientes valores hacen referencia al comando READ BINARY
              * 
              */
             
            final byte CLA = (byte) 0x00;// El valor 0x0X puede ir desde 0 a F en hexadecimal (0 hasta 15 en decimal).
            final byte INS = (byte) 0xB0;// Especifíca que el tipo de comando es un READ BINARY.
            final byte LE = (byte) 0xFF;//  LE: Número de bytes a leer (si está a 0, lee hasta 256).

            //[4] PRACTICA 3. Punto 1.b
            command = new byte[]{CLA, INS, (byte) bloque/*P1*/, (byte) 0x00/*P2*/, LE};//Realiza una lectura de todos los bytes excepto el rango P1 y P2, en este caso están a cero. 
            r = ch.transmit(new CommandAPDU(command));

            System.out.println("ACCESO DNIe: Response SW1=" + String.format("%X", r.getSW1()) + " SW2=" + String.format("%X", r.getSW2()));
            // El SW1=90 significa comando correcto OK
            
            if ((byte) r.getSW() == (byte) 0x9000) {
                r2 = r.getData();

                baos.write(r2, 0, r2.length);

                for (int i = 0; i < r2.length; i++) {
                    byte[] t = new byte[1];
                    t[0] = r2[i];
                    System.out.println(i + (0xff * bloque) + String.format(" %2X", r2[i]) + " " + String.format(" %d", r2[i])+" "+new String(t));
                }
                bloque++;
            } else {
                return null;
            }

        } while (r2.length >= 0xfe);


         ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

      

        
        return baos.toByteArray();
    }

    
    
    
    /**
     * Este método establece la conexión con la tarjeta. La función busca el
     * Terminal que contenga una tarjeta, independientemente del tipo de tarjeta
     * que sea.
     *
     * @return objeto Card con conexión establecida
     * @throws Exception
     */
    private Card ConexionTarjeta() throws Exception {

        Card card = null;
        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        //System.out.println("Terminals: " + terminals);

        for (int i = 0; i < terminals.size(); i++) {

            // get terminal
            CardTerminal terminal = terminals.get(i);

            try {
                if (terminal.isCardPresent()) {
                    card = terminal.connect("*"); //T=0, T=1 or T=CL(not needed)
                }
            } catch (Exception e) {

                System.out.println("Exception catched: " + e.getMessage());
                card = null;
            }
        }
        return card;
    }

    /**
     * Este método nos permite saber el tipo de tarjeta que estamos leyendo del
     * Terminal, a partir del ATR de ésta.
     *
     * @param atrCard ATR de la tarjeta que estamos leyendo
     * @return tipo de la tarjeta. 1 si es DNIe, 2 si es Starcos y 0 para los
     * demás tipos
     */
    private boolean esDNIe(byte[] atrCard) {
        int j = 0;
        boolean found = false;

        //Es una tarjeta DNIe?
        if (atrCard.length == dnie_v_1_0_Atr.length) {
            found = true;
            while (j < dnie_v_1_0_Atr.length && found) {
                if ((atrCard[j] & dnie_v_1_0_Mask[j]) != (dnie_v_1_0_Atr[j] & dnie_v_1_0_Mask[j])) {
                    found = false; //No es una tarjeta DNIe
                }
                j++;
            }
        }

        if (found == true) {
            return true;
        } else {
            return false;
        }

    }

    /**
     * Analizar los datos leídos del DNIe para obtener
     *   - nombre
     *   - apellidos
     *   - NIF
     * @param datos
     * @return 
     */
    private Usuario leerDatosUsuario(byte[] datos) throws KeyStoreException, UnsupportedEncodingException, NoSuchAlgorithmException {
        

        byte[] dni= new byte[9];
        int cont=0;
        int tam=-1;
        byte[] nombre= null;
        boolean pos=false;
        int i=0,j=0;
        String DNI="",NOMBRE="",n="",a1="",a2="", NICK="";
        
        
        //Se extrae bytes del nombre y apellidos despues de encontrar TIPO UTF8
        //Este for es para el DNI
        
        for(i=0;i<datos.length;i++){
        
            
            if(datos[i]==6 && datos[i+2]==85 && datos[i+3]==4 && datos[i+4]==5){
            i=i+6;//Salto el tamaño del DNI y me coloco en la primera letra.
            pos=true;
            }else if(cont<9 && pos==true){
            dni[cont]=datos[i];
            cont++;
            }else if (cont==9){
                cont=0;pos=false;
                j=i;//Guardo la posicion donde he terminado el DNI para seguir en el siguiente for
                i=datos.length;
        DNI= new String(dni);//Para convertir los bytes del array dni a String
            }
        
        }
                
        //Este for para recoger el nombre y apellidos    
        for(j=0;j<datos.length;j++){
        
            if(datos[j]==6 && datos[j+2]==85 && datos[j+3]==4 && datos[j+4]==3){
            j=j+5;//Me coloco en la posicion de UTF8Stringtype 12
            pos=true;
            
            }if(datos[j]==12 && pos==true){
            
            tam= (int)datos[j+1];//El siguiente byte indica el tamaño del nombre, lo guardamos.
            nombre= new byte[tam];//Inicializamos con ese tamaño.
            j=j+2;// y ya nos colocamos en la primera letra del nombre.
            pos=false;
            }if(cont<tam && pos==false){//Recorremos hasta los bytes que hemos recogido en la variable tam.
                nombre[cont]=datos[j];
                cont++;
            }else if(cont==tam){
            
            j=datos.length;
            NOMBRE=new String(nombre);
            }
        }
                

///+++++++++++++++++++++ FORMATEAMOS LOS DATOS OBTENIDOS ++++++++++++++++++++++++++++++++++
        String[] nomb,apellidos;
        nomb=NOMBRE.split(",");
        apellidos=NOMBRE.split(",");
        nomb=nomb[1].split(Pattern.quote("(AUTENTICACIÓN)"));
        n=nomb[0].trim();//Quitar espacios nombre
     
        apellidos=apellidos[0].split(" ");
        a1=apellidos[0];
        a2=apellidos[1];
        NICK=n.substring(0,1)+ a1 + a2.substring(0,1);
        Usuario user= new Usuario(n, a1, a2, DNI, NICK);
        

       
JOptionPane.showMessageDialog(null, "Lectura DNIe:" + n + " " + a1 + " " + a2 + " "+ DNI + " "+ NICK);
       return user;
    }
    

    
}