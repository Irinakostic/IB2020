package app;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Key;
import java.security.PrivateKey;
import java.security.Security;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import keystore.KeyStoreReader;
import model.IssuerData;
import support.MailHelper;
import support.MailReader;

public class ReadMailClient extends MailClient {
	
	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	private static final String USER_A_JKS = "./data/userajks.jks";
	private static final String USER_B_JKS = "./data/userbjks.jks";
	private static final String userBAlias = "userB";
	private static final String userAAlias = "userA";
	private static final String userBPass = "sifrab";
	private static final String userAPass = "sifraa";
	
	
	static {
		//staticka inicijalizacija
        Security.addProvider(new BouncyCastleProvider());
        org.apache.xml.security.Init.init();
	}
	
	public static void main(String[] args) throws Exception {
        // Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
        
        //Izlistavanje prvih PAGE_SIZE mail-ova prve stranice.
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\nMessage number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
        
        //odabir mail-a od strane korisnika
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
		MimeMessage chosenMessage = mimeMessages.get(answer);
	    
        //izvlacenje teksta mail-a koji je trenutno u obliku stringa
		String xmlAsString = MailHelper.getText(chosenMessage);
		
		//kreiranje XML dokumenta na osnovu stringa
		Document doc = createXMlDocument(xmlAsString);
		
		Element element = (Element)doc.getElementsByTagName("mail").item(0);
		
		// citanje keystore-a kako bi se izvukao sertifikat primaoca
		// i kako bi se dobio njegov tajni kljuc
		PrivateKey privateKey = getPrivateKey();
		
		System.out.println(privateKey.toString());
					
		//desifrovanje tajnog (session) kljuca pomocu privatnog kljuca
		//xmlcipher.aes_128 dodano
		XMLCipher xmlCipher = XMLCipher.getInstance();
		xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
		
		
		//TODO 2 
		EncryptedData encryptedData = xmlCipher.loadEncryptedData(doc, element);
		KeyInfo ki = encryptedData.getKeyInfo();
		EncryptedKey encKey = ki.itemEncryptedKey(0);
		
		XMLCipher keyCipher = XMLCipher.getInstance();
		keyCipher.init(XMLCipher.UNWRAP_MODE, privateKey);
		Key key = keyCipher.decryptKey(encKey,encryptedData.getEncryptionMethod().getAlgorithm());
		xmlCipher.init(XMLCipher.DECRYPT_MODE, key);
		xmlCipher.setKEK(key);
		
		
		//TODO 3 trazi se prvi EncryptedData element i izvrsi dekriptovanje
		

		System.out.println("Body text: " + element.getTextContent());
		
		Document doc2 = xmlCipher.doFinal(doc, element,true);
		System.out.println(xmlAsString(doc2));
		
		
		
		
	}
	
	private static String xmlAsString(Document doc) throws TransformerException{
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(doc), new StreamResult(writer));
		String output = writer.getBuffer().toString().replaceAll("\n|\r", "");
		
		return output;
	}
	
	private static Document createXMlDocument(String xmlAsString){
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();  
		factory.setNamespaceAware(true);
		DocumentBuilder builder;  
		Document doc = null;
		try {  
		    builder = factory.newDocumentBuilder();  
		    doc = builder.parse(new InputSource(new StringReader(xmlAsString)));  
		} catch (Exception e) {  
		    e.printStackTrace();  
		} 
		return doc;
	}
	
	// TODO 1 - izvlaci tajni kljuc iz sertifikata B
	private static PrivateKey getPrivateKey() {
		KeyStoreReader keyStoreReader = new KeyStoreReader();
		IssuerData issuerData = null;

		try {
			issuerData = keyStoreReader.readKeyStore(USER_B_JKS, userBAlias, userBPass.toCharArray() , userBPass.toCharArray());
			PrivateKey privateKey = issuerData.getPrivateKey();
			return privateKey;
		} catch (ParseException e) {
			e.printStackTrace();
		}
		
		
		
		return null;
	}

}
