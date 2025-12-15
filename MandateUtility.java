package com.tcs.sbi.util;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
//import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.stream.Stream;
import java.util.zip.ZipInputStream;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPUtil;
import com.tcs.sbi.launcher.MandateLauncher;

public class MandateUtility {

	private static final Logger log = LogManager.getLogger(MandateLauncher.class);

	public static boolean typeValidation(File file) {
		boolean isFile = false;
		if (file.isFile()) {
			isFile = true;
		}
		return isFile;
	}

	public static boolean extensionValidation(File file) {
		boolean isZipFile = false;
		String extension = FilenameUtils.getExtension(file.getName());
		if (extension.equalsIgnoreCase("zip")) {
			isZipFile = true;
		}
		return isZipFile;

	}

	public static String generateReferenceNumber() {
		String generateUUIDNo = String.format("%010d",
				new BigInteger(UUID.randomUUID().toString().replace("-", ""), 16));
		String unique_no = "SBIN" + generateUUIDNo.substring(generateUUIDNo.length() - 10);

		return unique_no;
	}

	public static void deleteDirectoryRecursively(Path path) throws IOException {
		if (Files.exists(path)) {
			try (Stream<Path> walk = Files.walk(path)) {
				walk.sorted((a, b) -> b.compareTo(a)).forEach(p -> {
					try {
						Files.deleteIfExists(p);
					} catch (IOException e) {
						throw new RuntimeException("Failed to delete " + p + " : " + e.getMessage());
					}
				});
			}
		}
	}
	public static void copyFolder(Path source,Path target) throws IOException {
		Files.walkFileTree(source,new SimpleFileVisitor<Path>() {
			@Override public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
				Path targetDir = target.resolve(source.relativize(dir));
				if(!Files.exists(targetDir)) {
					Files.createDirectory(targetDir);
				}
				return FileVisitResult.CONTINUE;
			}
			@Override public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
				Path targetFile = target.resolve(source.relativize(file));
				Files.copy(file, targetFile,StandardCopyOption.REPLACE_EXISTING);
				return FileVisitResult.CONTINUE;
			}
			
			@Override public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException{
				log.info("Failed to copy the folder" + file + " : " + exc.getMessage());
				return FileVisitResult.CONTINUE;
			}
		});
	}

	public static boolean unzip(File file, String destPath) throws IOException {

		boolean isunzipped = false;
		String dest = "";
		try {

			ZipFile zipfile = new ZipFile(file.getAbsolutePath());
			Enumeration<? extends ZipEntry> entries = zipfile.entries();
			while (entries.hasMoreElements()) {
				ZipEntry entry = entries.nextElement();
				String filepath = destPath + File.separator + (entry.getName());
				File filecontent = new File(filepath);
				File parentDir = filecontent.getParentFile();
				if (!parentDir.exists()) {
					parentDir.mkdirs();
				}
				if (FilenameUtils.getExtension(getRelativePath(entry.getName())).equalsIgnoreCase("xml")) {
					File xml = new File(parentDir + File.separator + "XMLFILES");
					if (!xml.exists()) {
						xml.mkdirs();
					}
					dest = xml.getAbsolutePath() + File.separator + getRelativePath(entry.getName());

				} else if (FilenameUtils.getExtension(getRelativePath(entry.getName())).equalsIgnoreCase("tif")
						|| FilenameUtils.getExtension(getRelativePath(entry.getName())).equalsIgnoreCase("jpeg")
						|| FilenameUtils.getExtension(getRelativePath(entry.getName())).equalsIgnoreCase("jpg")
						|| FilenameUtils.getExtension(getRelativePath(entry.getName())).equalsIgnoreCase("tiff")) {
					File images = new File(parentDir + File.separator + "IMAGES");
					if (!images.exists()) {
						images.mkdirs();
					}
					dest = images.getAbsolutePath() + File.separator + getRelativePath(entry.getName());
				}
				try (InputStream is = zipfile.getInputStream(entry); FileOutputStream os = new FileOutputStream(dest)) {
					byte[] buffer = new byte[1024];
					int bytesRead;
					while ((bytesRead = is.read(buffer)) != -1) {
						os.write(buffer, 0, bytesRead);

					}
				}

			}
			isunzipped = true;
			zipfile.close();
			System.out.println("Unzipped Completed");

		} catch (Exception e) {
			System.out.println(e.getMessage());
		}

		return isunzipped;
	}

//	public static void unzipfrombytes(byte[] zipbytes) {
//		try(InputStream bytestream=new ByteArrayInputStream(zipbytes);
//				ZipInputStream zis=new ZipInputStream(bytestream)){
//			
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//	}

	public static int returnMaxDays(int calMonth) {

		int maxDays = 0;

		if (calMonth == 1) {
			maxDays = 31;
		} else if (calMonth == 2) {
			maxDays = 28;
		} else if (calMonth == 3) {
			maxDays = 31;
		} else if (calMonth == 4) {
			maxDays = 30;
		} else if (calMonth == 5) {
			maxDays = 31;
		} else if (calMonth == 6) {
			maxDays = 30;
		} else if (calMonth == 7) {
			maxDays = 31;
		} else if (calMonth == 8) {
			maxDays = 31;
		} else if (calMonth == 9) {
			maxDays = 30;
		} else if (calMonth == 10) {
			maxDays = 31;
		} else if (calMonth == 11) {
			maxDays = 30;
		} else {
			maxDays = 31;
		}
		return maxDays;
	}

	public static boolean unzipfrombytes(String filename, byte[] zipbytes) {
		boolean isUnzipped = false;
		File outputfolder = null;

		outputfolder = new File(MandateLauncher.getDestDir() + File.separator + filename);
		if (!outputfolder.exists()) {
			outputfolder.mkdir();
		}
		InputStream byteArrayInputStream = new ByteArrayInputStream(zipbytes);
		ZipInputStream zis = new ZipInputStream(byteArrayInputStream);
		ZipEntry zipEntry;
		try {
			zipEntry = zis.getNextEntry();
			while (zipEntry != null) {
				File newFile = new File(outputfolder.getAbsolutePath(), zipEntry.getName());
				Files.copy(zis, Paths.get(newFile.getAbsolutePath()), StandardCopyOption.REPLACE_EXISTING);
				zipEntry = zis.getNextEntry();
			}
			isUnzipped = true;
			zis.close();
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println(e);
		}

		return isUnzipped;
	}

//		System.out.println(outputfile.getAbsolutePath());
//		tempFile=tempFilePath.toFile();
//		System.out.println(tempFile.getName());

	private static String getRelativePath(String entryName) {
		int firstSlashIndex = entryName.indexOf('/');
		if (firstSlashIndex != -1) {
			return entryName.substring(firstSlashIndex + 1);
		}
		return entryName;
	}

	@SuppressWarnings("unchecked")
//	public static boolean rsaDecryptFile(InputStream in, PGPPrivateKey priK, String filename, String decfilePath) {
//		boolean isdecrypted = false;
//		try {
//
//			in = PGPUtil.getDecoderStream(in);
//			System.out.println("excuted 1");
//			PGPObjectFactory pgpFactory = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
//
//			Object obj = pgpFactory.nextObject();
//
//			if (obj instanceof PGPEncryptedDataList) {
//				System.out.println("Decoded stream contains PGP Encrypted Data.");
//			} else {
//				System.out.println("Decoded stream does not contain PGP Encrypted Data.");
//			}
//			System.out.println("excuted 2");
//			PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) pgpFactory.nextObject();
//			System.out.println(encryptedDataList);
//			System.out.println("excuted 3");
//
//			Iterator<PGPEncryptedData> it = encryptedDataList.getEncryptedDataObjects();
//
//			PGPPrivateKey sKey = null;
//			PGPPublicKeyEncryptedData pbe = null;
//			while (sKey == null && it.hasNext()) {
//				pbe = (PGPPublicKeyEncryptedData) it.next();
//				sKey = priK;
//
//			}
//			if (sKey == null) {
//				throw new IllegalArgumentException("Secret key for message not found.");
//			}
//			PublicKeyDataDecryptorFactory b = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC")
//					.setContentProvider("BC").build(sKey);
//
//			InputStream clear = pbe.getDataStream(b);
//
//			isdecrypted = true;
//
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (PGPException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//
//		return isdecrypted;
//	}

	public static HashMap<String, String> rsaDecryptFile(InputStream in, PGPPrivateKey priK, String filename,
			String decfilePath) {
//		log.info("prik"+priK);
//		log.info("filename"+filename);
//		log.info("decfilepath"+decfilePath);
		HashMap<String, String> dMap = new HashMap<String, String>();
		dMap.put("FileName", filename);

		try {
			Security.addProvider(new BouncyCastleProvider());

			in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
			PGPObjectFactory pgpF = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
			PGPEncryptedDataList enc;
			Object o = pgpF.nextObject();
			log.info( o instanceof PGPEncryptedDataList);
			if (o instanceof PGPEncryptedDataList) {
				enc = (PGPEncryptedDataList) o;
				//log.info("1");
			} else {
				enc = (PGPEncryptedDataList) pgpF.nextObject();
				log.error("else case:"+enc);

			}

			@SuppressWarnings("unchecked")
			Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
			PGPPrivateKey sKey = null;
			PGPPublicKeyEncryptedData pbe = null;

			while (sKey == null && it.hasNext()) {
				//log.info("11");
				pbe = (PGPPublicKeyEncryptedData) it.next();
				sKey = priK;

			}
			//log.info("2");
			if (sKey == null) {
				throw new IllegalArgumentException("Secret key for message not found.");
			}
			PublicKeyDataDecryptorFactory b = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC")
					.setContentProvider("BC").build(sKey);
			//log.info("3 "+pbe+" "+b);
			InputStream clear = pbe.getDataStream(b);
				//log.info("4");
				if (clear == null) {
				    throw new IOException("Failed to obtain data stream from PBE.");
				}
	            PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
	            Object message = plainFact.nextObject();

	            if (message instanceof PGPCompressedData) {
	                PGPCompressedData cData = (PGPCompressedData) message;
	                PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(),
	                        new JcaKeyFingerprintCalculator());
	                message = pgpFact.nextObject();
	                //log.info("5");
	            }

	            if (message instanceof PGPLiteralData) {
	                PGPLiteralData ld = (PGPLiteralData) message;
	                //log.info("6");
	                try (InputStream unc = ld.getInputStream()) {
//	                    FileUtils.copyInputStreamToFile(unc, new File(decfilePath + filename)); 
	                	File file = new File(decfilePath + filename);
	                	//log.info(file.getAbsolutePath());
	                    FileUtils.copyInputStreamToFile(unc, file);
	                    //log.info("File exists after copy? " + file.exists());
	                } catch (Exception e){
	                	log.info(e.getMessage());
	                }
	            } else if (message instanceof PGPOnePassSignatureList) {
	                throw new PGPException("Encrypted message contains a signed message - not literal data.");
	            } else {
	                throw new PGPException("Message is not a simple encrypted file - type unknown.");
	            }

	            if (pbe.isIntegrityProtected()) {
	                if (!pbe.verify()) {
	                    throw new PGPException("Message failed integrity check");
	                }
	            }
	        

		} catch (PGPException e) {
			System.out.println("e1"+e);
			log.info(e);
			dMap.put("ERROR", "PGPDecryptionError");
		} catch (Exception e) {
			System.out.println("e2"+e);
			log.info(e);
			dMap.put("Error", "DecryptionError-File not exactly encrypted");
		}
		return dMap;

	}
	
	public static HashMap<String,String> rsaDecryptFile1(InputStream in, PGPPrivateKey priK, String fileName, String decFilePath){
		HashMap<String, String> dMap = new HashMap<>();
		dMap.put("FileName",fileName);
		try {
			Security.addProvider(new BouncyCastleProvider());
			InputStream armoredIn = new ArmoredInputStream(in);
			PGPObjectFactory pgpF = new PGPObjectFactory(armoredIn, new JcaKeyFingerprintCalculator());
			PGPEncryptedDataList enc = null;
			Object o;
			while((o = pgpF.nextObject()) != null) {
				if(o instanceof PGPEncryptedDataList) {
					enc = (PGPEncryptedDataList) o;
					break;
				}
			}
			if(enc == null) {
				throw new PGPException("Encrypted data list not found in stream");
			}
			
			PGPPublicKeyEncryptedData pbe = (PGPPublicKeyEncryptedData) enc.get(0);
			
			InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(priK));
			PGPObjectFactory plainFact = new PGPObjectFactory(clear,new JcaKeyFingerprintCalculator());
			Object message = plainFact.nextObject();
			if(message instanceof PGPCompressedData) {
				PGPCompressedData cData = (PGPCompressedData) message;
				PGPObjectFactory pgpFacto = new PGPObjectFactory(cData.getDataStream(), new JcaKeyFingerprintCalculator());
				message = pgpFacto.nextObject();
			}
			if(message instanceof PGPLiteralData) {
				PGPLiteralData ld = (PGPLiteralData) message;
				try(InputStream unc = ld.getInputStream()){
					File outputFile = new File(decFilePath + File.separator + fileName);
					FileUtils.copyInputStreamToFile(unc,outputFile);
				}
			} else {
				throw new PGPException("Message is not a simple literal data packet");
			}
			
			if(pbe.isIntegrityProtected() && !pbe.verify()) {
				throw new PGPException("Message failed integrity check : data may be corrupt or tampered with.");
			}
			dMap.put("SUCCESS","Decryption SuccessFul");
		} catch(Exception e) {
			dMap.put("ERROR","DecryptionError: " + e.getMessage());
			e.printStackTrace();
			System.out.println(e);
		}
		
		return dMap;
	}

	public static PrivateKey getCertKeys(String cerFileStream, String password) throws Exception {

		KeyStore keyStore = KeyStore.getInstance("PKCS12"); // , "BC");
		try (FileInputStream fis = new FileInputStream(cerFileStream)) {
			keyStore.load(fis, password.toCharArray());
		}
		String aliase = keyStore.aliases().nextElement();
		java.security.Key key = keyStore.getKey(aliase, password.toCharArray());

		return (PrivateKey) key;
	}

	public static PublicKey getPubkeyfrompath(String pupkeypath) {
		PublicKey pubkey;
		try {
			CertificateFactory certfactory = CertificateFactory.getInstance("X.509");
			FileInputStream fis = new FileInputStream(pupkeypath);
			Certificate certificate = certfactory.generateCertificate(fis);

			pubkey = certificate.getPublicKey();
			return pubkey;
		} catch (Exception e) {

			return null;
		}

	}

	public static Timestamp getTimestamp() {
		Timestamp timestamp = null;
		try {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");
			String strTime = sdf.format(new Date());
			timestamp = Timestamp.valueOf(strTime);
		} catch (IllegalArgumentException e) {
			log.error("Invalid timestamp format: {}", e.getMessage(), e);
		} catch (NullPointerException e) {
			log.error("Timestamp string is null: {}", e.getMessage(), e);
		} catch (Exception e) {
			log.error("An unexpected error occurred: {}", e.getMessage(), e);
		}
		return timestamp;
	}

	public static String readXMLContent(File file) {
		String targetfile = file.getName().replaceAll("\\.zip$", ".txt");
		targetfile = MandateLauncher.getDecFilePath() + File.separator + targetfile;
		InputStream SourceFileInputStream = null;
		try {
			SourceFileInputStream = new FileInputStream(file.getAbsolutePath());
			FileUtils.copyInputStreamToFile(SourceFileInputStream, new File(targetfile));
//			System.out.println("Completed");
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				SourceFileInputStream.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return targetfile;
	}

	public static boolean isPGPEncrypted(String file) throws IOException {
		boolean isPGPEncrypted = false;
		boolean hasBeginMarker = false;
		boolean hasEndMarker = false;

		try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
			String line;
			while ((line = reader.readLine()) != null) {
				if (line.contains("-----BEGIN PGP MESSAGE-----")) {
					hasBeginMarker = true;
				}
				if (line.contains("-----END PGP MESSAGE-----")) {
					hasEndMarker = true;
				}
				// If both markers are found, we can break early
				if (hasBeginMarker && hasEndMarker) {
					isPGPEncrypted = true;
					break;
				}
			}
			reader.close();
		} catch (FileNotFoundException e) {
			log.error("File not found: ", e);
		} catch (IOException e) {
			log.error("I/O error occurred while reading the file: ", e);
		} catch (NullPointerException e) {
			log.error("File reference is null: ", e);
		} catch (Exception e) {
			log.error("Unexpected error: ", e);
		}
		// Return true only if both markers are present
		return isPGPEncrypted && hasBeginMarker && hasEndMarker;
	}

	@SuppressWarnings("unused")
	public static String[] extractalldata(String decfile) {
		String[] extractedData = new String[3];
		try {
			File inputfile = new File(decfile);
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docx = factory.newDocumentBuilder();
			Document doc = docx.parse(inputfile);
			doc.getDocumentElement().normalize();
			Element Rootelement = doc.getDocumentElement();

			Node orgContent = doc.getElementsByTagName("OrgContent").item(0);
			if (orgContent != null) {
				extractedData[0] = orgContent.getTextContent();
			}

			Node signature = doc.getElementsByTagName("Signature").item(0);
			if (signature != null) {
				extractedData[1] = signature.getTextContent();
			}

			Node certificate = doc.getElementsByTagName("Certificate").item(0);
			if (certificate != null) {
				extractedData[2] = certificate.getTextContent();
			}

		} catch (Exception e) {
			e.getMessage();
		}
		return extractedData;
	}

	public static X509Certificate getX509Certificate(byte[] cert) throws CertificateException, IOException {
		X509Certificate certificate = null;

		try {
			InputStream stream = new ByteArrayInputStream(cert);
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			certificate = (X509Certificate) certificateFactory.generateCertificate(stream);
			stream.close();
		} catch (Exception e) {
			e.getMessage();
		}

		return certificate;
	}

	public static String generateRefrenceNumber() {

		String generateUUIDNo = String.format("%010d",
				new BigInteger(UUID.randomUUID().toString().replace("-", ""), 16));
		String unique_no = "SBIN" + generateUUIDNo.substring(generateUUIDNo.length() - 10);

		return unique_no;

	}

	public static boolean isSignedFile(String file) throws IOException {
		boolean isSigned = false;
		boolean has1 = false;
		boolean has2 = false;
		boolean has3 = false;
		boolean has4 = false;
		try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
			String line;
			while ((line = reader.readLine()) != null) {
				if (line.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Envelope><OrgContent>")) {
					has1 = true;
				}
				if (line.contains("</OrgContent><Signature>")) {
					has2 = true;
				}
				if (line.contains("</Signature><Certificate>")) {
					has3 = true;
				}
				if (line.contains("</Certificate></Envelope>")) {
					has4 = true;
				}
				if (has1 && has2 && has3 && has4) {
					isSigned = true;
					break;
				}

			}
			reader.close();
		} catch (FileNotFoundException e) {
			log.error("File not found: ", e);
		} catch (IOException e) {
			log.error("I/O error occurred while reading the file: ", e);
		} catch (NullPointerException e) {
			log.error("File reference is null: ", e);
		} catch (Exception e) {
			log.error("Unexpected error: ", e);
		}
		return has1 && has2 && has3 && has4 && isSigned;
	}

	public static boolean verifysign(String signature, X509Certificate cert, String orgcontent)
			throws CertificateException, Exception {
		boolean isSignvalid = false;
		byte[] digisignrecieved = null;
		byte[] orginalContent = null;

		try {

			try {
				digisignrecieved = Base64.getDecoder().decode(signature);
				orginalContent = Base64.getDecoder().decode(orgcontent);

			} catch (Exception e) {
				e.getMessage();
				isSignvalid = false;
			}
			CMSProcessableByteArray cmscontet = new CMSProcessableByteArray(orginalContent);
			CMSSignedData signeddata = new CMSSignedData(cmscontet, digisignrecieved);
			SignerInformationStore singer = signeddata.getSignerInfos();
			Collection<SignerInformation> signerinfo = singer.getSigners();

			for (SignerInformation signerInformation : signerinfo) {
				if (signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().build(cert))) {

					isSignvalid = true;
				} else {

					isSignvalid = false;
				}
			}
		} catch (CMSException e) {
		    log.error("CMS processing error: ", e);
		    isSignvalid = false;
		} catch (Exception e) {
			log.error("An unexpected error occurred: ", e);
			isSignvalid = false;
		}

		return isSignvalid;

	}

}
