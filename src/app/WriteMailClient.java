package app;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.text.ParseException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.mail.internet.MimeMessage;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.CipherData;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.EncryptionMethod;
import org.apache.xml.security.encryption.EncryptionProperties;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.KeyName;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.api.services.gmail.Gmail;

import keystore.KeyStoreReader;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {
	
	private static final String USER_A_JKS = "./data/userajks.jks";
	private static final String USER_B_JKS = "./data/userbjks.jks";
	private static final String userBAlias = "userB";
	private static final String userAAlias = "userA";
	private static final String userBPass = "sifrab";
	private static final String userAPass = "sifraa";
	static {
		// staticka inicijalizacija
		Security.addProvider(new BouncyCastleProvider());
		org.apache.xml.security.Init.init();
	}

	public static void main(String[] args) {

		try {
			Gmail service = getGmailService();

			// Unos podataka
			System.out.println("Insert a reciever:");
			BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
			String reciever = reader.readLine();

			System.out.println("Insert a subject:");
			String subject = reader.readLine();

			System.out.println("Insert body:");
			String body = reader.readLine();

			// kreiraj xml dokument
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

			Document doc = docBuilder.newDocument();
			Element rootElement = doc.createElement("mail");

			rootElement.setTextContent(body);
			doc.appendChild(rootElement);

			// dokument pre enkripcije
			String xml = xmlAsString(doc);
			System.out.println("Mail pre enkripcije: " + xml);

			// generisanje tajnog (session) kljuca
			SecretKey secretKey = generateSessionKey();

			// citanje keystore-a kako bi se izvukao sertifikat primaoca
			// i kako bi se dobio njegov javni kljuc
			PublicKey publicKey = getPublicKey();

			// inicijalizacija radi sifrovanja teksta mail-a
			XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
			xmlCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);

			// inicijalizacija radi sifrovanja tajnog (session) kljuca javnim RSA kljucem
			XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
			keyCipher.init(XMLCipher.WRAP_MODE, publicKey);

			// TODO 3: kreiranje EncryptedKey objekta koji sadrzi enkriptovan tajni
			// (session) kljuc
			EncryptedKey encryptedKey = keyCipher.encryptKey(doc, secretKey);
			System.out.println("Tajni kljuc(kriptovan): " + encryptedKey);
			
			//TODO 4: kreiranje KeyInfo objekta, postavljanje naziva i enkriptovanog tajnog kljuca
			KeyInfo keyInfo = new KeyInfo(doc); 
			keyInfo.add(new KeyName(doc, "encryptedKey"));
			keyInfo.add(encryptedKey);
			
			
			//TODO 5: kreiranje EncryptedData objekata, postavljanje KeyInfo objekata
			EncryptedData encryptedData = new EncryptedData() {
				
				@Override
				public void setType(String arg0) {
					// TODO Auto-generated method stub
					
				}
				
				@Override
				public void setMimeType(String arg0) {
					// TODO Auto-generated method stub
					
				}
				
				@Override
				public void setKeyInfo(KeyInfo arg0) {
					// TODO Auto-generated method stub
					
				}
				
				@Override
				public void setId(String arg0) {
					// TODO Auto-generated method stub
					
				}
				
				@Override
				public void setEncryptionProperties(EncryptionProperties arg0) {
					// TODO Auto-generated method stub
					
				}
				
				@Override
				public void setEncryptionMethod(EncryptionMethod arg0) {
					// TODO Auto-generated method stub
					
				}
				
				@Override
				public void setEncoding(String arg0) {
					// TODO Auto-generated method stub
					
				}
				
				@Override
				public String getType() {
					// TODO Auto-generated method stub
					return null;
				}
				
				@Override
				public String getMimeType() {
					// TODO Auto-generated method stub
					return null;
				}
				
				@Override
				public KeyInfo getKeyInfo() {
					// TODO Auto-generated method stub
					return null;
				}
				
				@Override
				public String getId() {
					// TODO Auto-generated method stub
					return null;
				}
				
				@Override
				public EncryptionProperties getEncryptionProperties() {
					// TODO Auto-generated method stub
					return null;
				}
				
				@Override
				public EncryptionMethod getEncryptionMethod() {
					// TODO Auto-generated method stub
					return null;
				}
				
				@Override
				public String getEncoding() {
					// TODO Auto-generated method stub
					return null;
				}
				
				@Override
				public CipherData getCipherData() {
					// TODO Auto-generated method stub
					return null;
				}
			};
			EncryptedData encData = xmlCipher.getEncryptedData();
			encData.setKeyInfo(keyInfo);
				
			encryptedData.setKeyInfo(keyInfo);

			//TODO 6: kriptovati sadrzaj dokumenta
			xmlCipher.doFinal(doc, rootElement,true );

			// Slanje poruke
			String encryptedXml = xmlAsString(doc);
			System.out.println("Mail posle enkripcije: " + encryptedXml);

			MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, subject, encryptedXml);
			MailWritter.sendMessage(service, "me", mimeMessage);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static String xmlAsString(Document doc) throws TransformerException {
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(doc), new StreamResult(writer));
		String output = writer.getBuffer().toString().replaceAll("\n|\r", "");

		return output;
	}

	// TODO 1 - generisi tajni (session) kljuc
	private static SecretKey generateSessionKey() {
		
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("TRIPLEDES");
			keyGenerator.init(168);
			SecretKey secretKey = keyGenerator.generateKey();
			return secretKey;
		} catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
		return null;
	}

	// TODO 2 - iz sertifikata korisnika B izvuci njegov javni kljc
	private static PublicKey getPublicKey() {
		PublicKey userBPKey=new PublicKey() {
			
			/**
			 * 
			 */
			private static final long serialVersionUID = 1L;

			@Override
			public String getFormat() {
				// TODO Auto-generated method stub
				return null;
			}
			
			@Override
			public byte[] getEncoded() {
				// TODO Auto-generated method stub
				return null;
			}
			
			@Override
			public String getAlgorithm() {
				// TODO Auto-generated method stub
				return null;
			}
		};
		KeyStoreReader keyStoreReader = new KeyStoreReader();
		try {
			keyStoreReader.readKeyStore(USER_A_JKS, userBAlias, userAPass.toCharArray() , userBPass.toCharArray());
			userBPKey = keyStoreReader.readPublicKey();
		} catch (ParseException e) {
			e.printStackTrace();
		}
		
		
		
		return userBPKey;
	}

}
