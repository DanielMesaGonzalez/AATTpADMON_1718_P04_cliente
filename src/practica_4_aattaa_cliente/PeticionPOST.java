
package practica_4_aattaa_cliente;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import es.gob.jmulticard.jse.provider.DnieProvider;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Clase usada para generar la petición HTTP REQUEST de la aplicación cliente 
 * hacia el servidor 
 * @author Daniel Mesa y Salvador Trujillo
 */


public class PeticionPOST {
    private String DatosUsuario=""; 
    private URL URLServidor; 
    Usuario usu=new Usuario();
 
     public PeticionPOST(String URLServidor) throws MalformedURLException{ //Constructor. throws MalformedURLException: Excepción de error en la URL.
        this.URLServidor =new URL(URLServidor);
        this.DatosUsuario="";
    }

    public String getDatosUsuario() {
        return DatosUsuario;
    }

    public void setDatosUsuario(String DatosUsuario) {
        this.DatosUsuario=DatosUsuario;
    }

    String NotFound="ERROR 401:  USUARIO NO ENCONTRADO";   //Variable para comparar la respuesta del Servidor.
    String Found="200 OK:  USUARIO AUTENTICADO CORRECTAMENTE"; //Variable para comparar la respuesta del Servidor.
  
    public String Hash(Usuario usu) throws NoSuchAlgorithmException, UnsupportedEncodingException{
        
        ///++++++++++++++++++ CREAMOS EL HASH ++++++++++++++++++++++++++++++++++++
        String password=""+usu.getNombre()+""+usu.getApellido1()+""+usu.getApellido2()+"+"+usu.getNif()+""+usu.getNick()+"";  //concatenamos los datos
        MessageDigest sha256=MessageDigest.getInstance("SHA-256");
        sha256.update(password.getBytes("UTF-8"));
        byte[] digest = sha256.digest();
        StringBuffer sb=new StringBuffer();
        for(int k=0;k<digest.length;k++){
          sb.append(String.format("%02x", digest[k]));
     }
        String hash=sb.toString(); //2bb80d5...527a25b
        
         //Codificamos el hash en base64 para evitar problemas en el servidor 
                String hash_codificado = Base64.encode(hash.getBytes());
              
        return hash_codificado;
    }
    
    /**
 * 
 * Método usado para codificar el nick y el nif que se va a enviar en la petición del 
 * cliente al servidor.
 * 
 * @param nick recogido de la tarjeta DNIe introducida en el lector
 * @param nif recogido de la tarjeta DNIe introducida en el lector
     * @throws java.io.UnsupportedEncodingException
 */
    public String CertificadoUsuario(Usuario usu) throws KeyStoreException, CertificateEncodingException{
            KeyStore dniKS = null;
        ///++++++++++++++++++++++++++++ Extraemos el certificado  +++++++++++++++++
        	if (dniKS == null) {
                    
         DnieProvider dniProvider = new DnieProvider(); //Instanciamos el proveedor, se activa el modo rapido y se añade
         System.setProperty("es.gob.jmulticard.fastmode", "true");  
    	 Security.addProvider(dniProvider);
    	 dniKS = KeyStore.getInstance("DNI");  //Se obtiene el almacen DNI y se carga
    	 
    	 try {
			dniKS.load(null,null);
		} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 

         //Obtenemos el certificado (con clave pública) de firma digital del DNI.
           Certificate authCert = (X509Certificate) dniKS.getCertificate("CertAutenticacion");
         
           //Codificamos el certificado en base64 para evitar problemas en el servidor
                String certificado_codificado = Base64.encode(authCert.getEncoded());
               
         return certificado_codificado;
           /*  
           //Obtenemos los datos del usuario apartir del certificado.
           user = new User(authCert);*/
         //Certificate authCertFirm = ks.getCertificate("CertFirmaDigital");
         
    	}
        return null;
        
    }
    
     public void add (String nick, String nif) throws UnsupportedEncodingException, NoSuchAlgorithmException, KeyStoreException, CertificateEncodingException{
		//codificamos cada uno de los valores
		if (DatosUsuario.length()>0)
		DatosUsuario+= "&"+ URLEncoder.encode(nick, "UTF-8")+ "=" +URLEncoder.encode(nif, "UTF-8");
		else
		DatosUsuario+= URLEncoder.encode(nick, "UTF-8")+ "=" +URLEncoder.encode(nif, "UTF-8");
               
                
	}
     
     /**
 * Aplicaciones TelemÃ¡ticas para la AdministraciÃ³n
 *  
 * Método usado para enviar y recibir los datos del servidor. Los datos de envío serán 
 * el nick y el nif del usuario y los de respuesta será un mensaje 200 OK o 401 BAD AUTORIZADO
 * 
 * @param nick recogido del DNIe 
 * @param nif recogido del DNIe
     * @return 
     * @throws java.net.MalformedURLException
 * 
 */
     
    public String Acceder (String nick, String nif, String fecha) throws MalformedURLException, IOException{ //throws MalformedURLException: Excepción de error en la URL.
		String respuesta = "";
		//abrimos la conexion
		URLConnection conn = URLServidor.openConnection();
                
     //++++++++++++++++++++++++++ ESCRIBIR +++++++++++++++++++++++++//
		
                 conn.setDoOutput(true);    //Especificamos que vamos a escribir
		OutputStreamWriter escribir = new OutputStreamWriter(conn.getOutputStream()); //Para obtener el flujo de lectura
		escribir.write(DatosUsuario); //Escribimos los datos del usuario
		escribir.close(); //Finalizamos la escritura
		
    //+++++++++++++++++++++++++ LECTURA DE FLUJO ++++++++++++++++++++++++++++++++++++++++++++++//
		BufferedReader lectura = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		String cadena;
                
		while ((cadena = lectura.readLine()) !=null) { //Realizamos la lectura concatenando la respuesta del jsp
		
                    if(NotFound.equals(cadena) || Found.equals(cadena)){
                        respuesta+= cadena;
                    }
                }
		return respuesta;
	}
  

        
  

}
