package com.tcs.sbi.launcher;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;

import com.tcs.sbi.constants.ErrorConstants;
import com.tcs.sbi.constants.MandateConstants;
import com.tcs.sbi.main.MandateMain;
import com.tcs.sbi.util.MandateDecProperties;
import com.tcs.sbi.util.MandateUtility;
import com.tcs.sbi.constants.MandateConstants;

public class MandateLauncher {
	private static final Logger log = LogManager.getLogger(MandateLauncher.class);
	private static String loggerPath;
	private static String sourcePath;
//	 ="E:\\MandateFilesStructure\\SourceFiles\\";
	private static String destDir;
//	 ="E:\\MandateFilesStructure\\DestinationFiles";
	private static String decFilePath;
	private static String tempFilePath;
	private static String failedFilesPath;
	private static String decryptedBackupPath;
	private static PublicKey pubkey;
	private static PGPPublicKey pgpPubkey;
	private static PrivateKey privkey;
	private static PGPPrivateKey pgpPrivKey;
	private static int threadSleepTime;
	private static String threadSleepTimeString;
	private static String decryptionFailedPath;
	private static String signNotVerifiedPath;
	private static String dataExtractionFailedPath;
	private static String nameValidationFailedPath;
	private static String dateValidationFailedPath;
	private static String xmlUnreadablePath;
	private static String notaZIPPath;
	private static String backUpPath;
	private static String publicKeyPath;
	private static String privateKeyPath;
	private static String createNameStart;
	private static String createNameEnd;
	private static String amendNameStart;
	private static String amendNameEnd;
	private static String cancelNameStart;
	private static String cancelNameEnd;
	private static String noOfDays;
	private static String imagePath;
	private static String checkingCertPath;
	private static int minNameLength;
	private static int maxNameLength;

	public static String getCheckingCertPath() {
		return checkingCertPath;
	}

	public static void setCheckingCertPath(String checkingCertPath) {
		MandateLauncher.checkingCertPath = checkingCertPath;
	}

	public static String getImagePath() {
		return imagePath;
	}

	public static void setImagePath(String imagePath) {
		MandateLauncher.imagePath = imagePath;
	}

	public static String getDateValidationFailedPath() {
		return dateValidationFailedPath;
	}

	public static void setDateValidationFailedPath(String dateValidationFailedPath) {
		MandateLauncher.dateValidationFailedPath = dateValidationFailedPath;
	}

	public static String getNoOfDays() {
		return noOfDays;
	}

	public static void setNoOfDays(String noOfDays) {
		MandateLauncher.noOfDays = noOfDays;
	}

	public static String getCreateNameStart() {
		return createNameStart;
	}

	public static void setCreateNameStart(String createNameStart) {
		MandateLauncher.createNameStart = createNameStart;
	}

	public static String getCreateNameEnd() {
		return createNameEnd;
	}

	public static void setCreateNameEnd(String createNameEnd) {
		MandateLauncher.createNameEnd = createNameEnd;
	}

	public static String getAmendNameStart() {
		return amendNameStart;
	}

	public static void setAmendNameStart(String amendNameStart) {
		MandateLauncher.amendNameStart = amendNameStart;
	}

	public static String getAmendNameEnd() {
		return amendNameEnd;
	}

	public static void setAmendNameEnd(String amendNameEnd) {
		MandateLauncher.amendNameEnd = amendNameEnd;
	}

	public static String getCancelNameStart() {
		return cancelNameStart;
	}

	public static void setCancelNameStart(String cancelNameStart) {
		MandateLauncher.cancelNameStart = cancelNameStart;
	}

	public static String getCancelNameEnd() {
		return cancelNameEnd;
	}

	public static void setCancelNameEnd(String cancelNameEnd) {
		MandateLauncher.cancelNameEnd = cancelNameEnd;
	}

	public static String getTempFilePath() {
		return tempFilePath;
	}

	public static void setTempFilePath(String tempFilePath) {
		MandateLauncher.tempFilePath = tempFilePath;
	}

	public static String getSourcePath() {
		return sourcePath;
	}

	public static void setsourcePath(String sourcePath) {
		MandateLauncher.sourcePath = sourcePath;
	}

	public static String getDestDir() {
		return destDir;
	}

	public static String getDecFilePath() {
		return decFilePath;
	}

	public static void setDecFilePath(String decFilePath) {
		MandateLauncher.decFilePath = decFilePath;
	}

	public static void setDestDir(String destDir) {
		MandateLauncher.destDir = destDir;
	}

	public static PublicKey getPubkey() {
		return pubkey;
	}

	public static void setPubkey(PublicKey pubkey) {
		MandateLauncher.pubkey = pubkey;
	}

	public static PGPPublicKey getPgpPubkey() {
		return pgpPubkey;
	}

	public static void setPgpPubkey(PGPPublicKey pgpPubkey) {
		MandateLauncher.pgpPubkey = pgpPubkey;
	}

	public static PrivateKey getPrivkey() {
		return privkey;
	}

	public static void setPrivkey(PrivateKey privkey) {
		MandateLauncher.privkey = privkey;
	}

	public static PGPPrivateKey getPgpPrivKey() {
		return pgpPrivKey;
	}

	public static void setPgpPrivKey(PGPPrivateKey pgpPrivKey) {
		MandateLauncher.pgpPrivKey = pgpPrivKey;
	}

	public static String getDecryptedBackupPath() {
		return decryptedBackupPath;
	}

	public static void setDecryptedBackupPath(String decryptedBackupPath) {
		MandateLauncher.decryptedBackupPath = decryptedBackupPath;
	}

	public static String getFailedFilesPath() {
		return failedFilesPath;
	}

	public static void setFailedFilesPath(String failedFilesPath) {
		MandateLauncher.failedFilesPath = failedFilesPath;
	}

	public static String getDecryptionFailedPath() {
		return decryptionFailedPath;
	}

	public static void setDecryptionFailedPath(String decryptionFailedPath) {
		MandateLauncher.decryptionFailedPath = decryptionFailedPath;
	}

	public static String getSignNotVerifiedPath() {
		return signNotVerifiedPath;
	}

	public static void setSignNotVerifiedPath(String signNotVerifiedPath) {
		MandateLauncher.signNotVerifiedPath = signNotVerifiedPath;
	}

	public static String getDataExtractionFailedPath() {
		return dataExtractionFailedPath;
	}

	public static void setDataExtractionFailedPath(String dataExtractionFailedPath) {
		MandateLauncher.dataExtractionFailedPath = dataExtractionFailedPath;
	}

	public static String getXMLUnreadablePath() {
		return xmlUnreadablePath;
	}

	public static void setXMLUnreadablePath(String xmlUnreadablePath) {
		MandateLauncher.xmlUnreadablePath = xmlUnreadablePath;
	}

	public static String getNotaZIPPath() {
		return notaZIPPath;
	}

	public static void setNotaZIPPath(String notaZIPPath) {
		MandateLauncher.notaZIPPath = notaZIPPath;
	}

	public static String getBackUpPath() {
		return backUpPath;
	}

	public static void setBackUpPath(String backUpPath) {
		MandateLauncher.backUpPath = backUpPath;
	}

	public static String getLoggerPath() {
		return loggerPath;
	}

	public static void setLoggerPath(String loggerPath) {
		MandateLauncher.loggerPath = loggerPath;
	}

	public static Logger getLog() {
		return log;
	}

	private static String getNameValidationFailedPath() {
		return nameValidationFailedPath;
	}

	private static void setNameValidationFailedPath(String nameValidationFailedPath) {
		MandateLauncher.nameValidationFailedPath = nameValidationFailedPath;
	}

	static {

		try {
			loggerPath = MandateDecProperties.getInstance().getProperty(MandateConstants.LOGGER_FILEPATH.toString());
			Configurator.initialize(null, loggerPath + MandateConstants.LOGGER_FILENAME.toString() + ".properties");
			createNameStart = MandateDecProperties.getInstance().getProperty("CREATE_NAME_START");
			createNameEnd = MandateDecProperties.getInstance().getProperty("CREATE_NAME_END");
			amendNameStart = MandateDecProperties.getInstance().getProperty("AMEND_NAME_START");
			amendNameEnd = MandateDecProperties.getInstance().getProperty("AMEND_NAME_END");
			cancelNameStart = MandateDecProperties.getInstance().getProperty("CANCEL_NAME_START");
			cancelNameEnd = MandateDecProperties.getInstance().getProperty("CANCEL_NAME_END");
			sourcePath = MandateDecProperties.getInstance().getProperty("SOURCE_PATH");
			destDir = MandateDecProperties.getInstance().getProperty("DESTINATION_PATH");
			decFilePath = MandateDecProperties.getInstance().getProperty("DECRYPTED_FILE_PATH");
			tempFilePath = MandateDecProperties.getInstance().getProperty("TEMPORARY_FILE_PATH");
			failedFilesPath = MandateDecProperties.getInstance().getProperty("FAILED_FILES_PATH");
			decryptionFailedPath = MandateDecProperties.getInstance().getProperty("DECRYPTION_FAILED_PATH");
			dataExtractionFailedPath = MandateDecProperties.getInstance().getProperty("DATA_EXTRACTION_FAILED_PATH");
			xmlUnreadablePath = MandateDecProperties.getInstance().getProperty("XML_UNREADABLE_PATH");
			notaZIPPath = MandateDecProperties.getInstance().getProperty("NOT_A_ZIP_PATH");
			backUpPath = MandateDecProperties.getInstance().getProperty("BACKUP_PATH");
			noOfDays = MandateDecProperties.getInstance().getProperty("NO_OF_DAYS");
			dateValidationFailedPath = MandateDecProperties.getInstance().getProperty("DATE_EXTRACTION_FAILED_PATH");
			nameValidationFailedPath = MandateDecProperties.getInstance().getProperty("NAME_VALIDATION_FAILED_PATH");
			decryptedBackupPath = MandateDecProperties.getInstance().getProperty("OUTPUT_BACKUP_PATH");
			threadSleepTimeString = MandateDecProperties.getInstance().getProperty("THREAD_SLEEP_TIME");
			threadSleepTime = Integer.parseInt(threadSleepTimeString);
			publicKeyPath = MandateDecProperties.getInstance().getProperty("PUBLIC_KEY_PATH");
			privateKeyPath = MandateDecProperties.getInstance().getProperty("PRIVATE_KEY_PATH");
			imagePath = MandateDecProperties.getInstance().getProperty("IMAGE_PATH");
			checkingCertPath = MandateDecProperties.getInstance().getProperty("CHECKING_CERT_PATH");
			minNameLength = Integer.parseInt(MandateDecProperties.getInstance().getProperty("MIN_NAME_LENGTH"));
			maxNameLength = Integer.parseInt(MandateDecProperties.getInstance().getProperty("MAX_NAME_LENGTH"));

//	   E:\Aadesh\Keys\Public_private_key\NACH branch Public key and private key

			Security.addProvider(new BouncyCastleProvider());
			pubkey = MandateUtility.getPubkeyfrompath(publicKeyPath);
//		System.out.println("pubkey :"+pubkey);
			pgpPubkey = (new JcaPGPKeyConverter().getPGPPublicKey(PGPPublicKey.RSA_GENERAL, pubkey,
					new java.util.Date()));
//		System.out.println("pgpPubkey :"+pgpPubkey);
//			String password = "PASSWORD@1";
			String password = "password";
			privkey = MandateUtility.getCertKeys(privateKeyPath, password);
//		System.out.println("privkey :"+privkey);
			pgpPrivKey = (new JcaPGPKeyConverter().getPGPPrivateKey(pgpPubkey, privkey));
//		System.out.println("pgpPrivKey :"+pgpPrivKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {

		while (true) {
			log.info(
					"********************************  || AADESH_ACH_MANDATE_DEC UTILITY STARTED ||  ***********************************\n");

			HashMap<String, Object> decdmap = new HashMap<String, Object>();
			boolean dbupdate = false;
			boolean isfileprocessed = false;
			String referenceNumber = "";

			Calendar cal = Calendar.getInstance();
			int dTm = Integer.parseInt(MandateLauncher.getNoOfDays());
			cal.add(Calendar.DATE, -dTm);
			String currMonth = "";
			String currentDate = "";
			int prevCalMonth = cal.get(Calendar.MONTH) + 1;
			int prevCalYear = cal.get(Calendar.YEAR);
			int prevCalDate = cal.get(Calendar.DATE);

			cal.add(Calendar.DATE, dTm);
			int currCalMonth = cal.get(Calendar.MONTH) + 1;
			int currCalYear = cal.get(Calendar.YEAR);
			int currCalDate = cal.get(Calendar.DATE);

			LocalDate startDate = LocalDate.of(prevCalYear, prevCalMonth, prevCalDate);
			LocalDate endDate = LocalDate.of(currCalYear, currCalMonth, currCalDate);

			try {
				String fullpath = sourcePath;
				File FileList = new File(fullpath);
				File[] listOfFiles = FileList.listFiles();
				log.info("Total Number of Files found in source file for ACH-MANDATE to be proceed is : "
						+ listOfFiles.length);
				if (listOfFiles.length > 0) {
					ArrayList<String> nameOfFiles = new ArrayList<String>();
					for (File file : listOfFiles) {
						String fileName = file.getName();
						// file extension validation
						referenceNumber = MandateUtility.generateReferenceNumber();

						decdmap.put("FileName", fileName);
						decdmap.put("fileCopiedTime", MandateUtility.getTimestamp());
						decdmap.put("RefrenceNumber", referenceNumber);
						System.out.println(fileName.length());
						if (fileName.length() < minNameLength || fileName.length() > maxNameLength) {
							log.info("File Name validation failed because of different name length : "
									+ fileName.length() + "\n Name : " + fileName);
							Files.move(Paths.get(fullpath + File.separator + fileName),
									Paths.get(getNameValidationFailedPath() + File.separator + fileName).normalize(),
									StandardCopyOption.REPLACE_EXISTING);
						}

						if (fileName.contains("-CREATE-")) {
							decdmap.put("FileType", ErrorConstants.CREATE_FILE_TYPE.toString());
						} else if (fileName.contains("-AMEND-")) {
							decdmap.put("FileType", ErrorConstants.AMEND_FILE_TYPE.toString());
						} else if (fileName.contains("-CANCEL-")) {
							decdmap.put("FileType", ErrorConstants.CANCEL_FILE_TYPE.toString());
						} else {
							decdmap.put("FileType", "null");
						}

						String[] parts = fileName.split("-");
						String dateStr = parts[3];
						DateTimeFormatter formatter = DateTimeFormatter.ofPattern("ddMMyyyy"); // adjust pattern to your
																								// date format

						try {
							LocalDate fileDate = LocalDate.parse(dateStr, formatter);
							if (MandateUtility.extensionValidation(file)) {
								if ((fileDate.isEqual(startDate) || fileDate.isAfter(startDate))
										&& (fileDate.isEqual(endDate) || fileDate.isBefore(endDate))) {
									if ((fileName.contains(createNameStart) && fileName.contains(createNameEnd))
											|| (fileName.contains(amendNameStart) && fileName.contains(amendNameEnd))
											|| (fileName.contains(cancelNameStart)
													&& fileName.contains(cancelNameEnd))) {
										nameOfFiles.add(fileName);
										log.info("Checking date : " + fileDate);
									} else {
										decdmap.put("Status", ErrorConstants.VALIDATION_FAILED.toString());
										decdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
										decdmap.put("statusDEC", ErrorConstants.VALIDATION_FAILED.name().toString());
										decdmap.put("ERROR_CODE", ErrorConstants.ERR01.name());

										log.info("File Name validation failed");
										Files.move(Paths.get(fullpath + File.separator + fileName),
												Paths.get(getNameValidationFailedPath() + File.separator + fileName)
														.normalize(),
												StandardCopyOption.REPLACE_EXISTING);
									}
								} else {
									decdmap.put("ReferenceNumber", referenceNumber);
									decdmap.put("Status", ErrorConstants.VALIDATION_FAILED.toString());
									decdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
									decdmap.put("statusDEC", ErrorConstants.VALIDATION_FAILED.name().toString());
									decdmap.put("ERROR_CODE", ErrorConstants.ERR03.name());

									log.info("File date mismatch, File Date : " + fileDate);
									Files.move(Paths.get(fullpath + File.separator + fileName), Paths
											.get(getDateValidationFailedPath() + File.separator + fileName).normalize(),
											StandardCopyOption.REPLACE_EXISTING);
								}
							} else {
								decdmap.put("RefrenceNumber", referenceNumber);
								decdmap.put("Status", ErrorConstants.VALIDATION_FAILED.toString());
								decdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
								decdmap.put("statusDEC", ErrorConstants.VALIDATION_FAILED.name().toString());
								decdmap.put("ERROR_CODE", ErrorConstants.ERR02.name());

								String baseDir = MandateLauncher.getNameValidationFailedPath();
								Path fileTypePath = Paths.get(baseDir);
								Files.move(Paths.get(file.getAbsolutePath()), fileTypePath,
										StandardCopyOption.REPLACE_EXISTING);
								log.info(fileName + " File format is other than zip format, hence file is moved to : "
										+ fileTypePath);
							}
						} catch (DateTimeParseException e) {
							log.warn("Filename does not contain a valid date: " + fileName);
						}
					}

					ExecutorService eService = Executors.newSingleThreadExecutor();

					try {
						if (nameOfFiles.size() > 0) {
							Runnable Task = new MandateMain(MandateLauncher.getSourcePath(),
									MandateLauncher.getDestDir());
							eService.execute(Task);
						} else {
							log.info("There are no files available to process, hence thread is going to sleep for "
									+ threadSleepTime);
							Thread.sleep(threadSleepTime);
						}
					} catch (Exception e) {
						log.error("Error executing decryption task: " + e.getMessage(), e);
					} finally {
						eService.shutdown();
						try {
							if (!eService.awaitTermination(60, TimeUnit.SECONDS)) {
								eService.shutdownNow();
							}
						} catch (InterruptedException ie) {
							eService.shutdownNow();
							Thread.currentThread().interrupt();
						}
					}

//						log.info("There are no files available to process, hence thread is going to sleep for "+threadSleepTime);
//						System.out.println("There are no files available to process hence thread is going to sleep for : " + threadSleepTime);
//						Thread.sleep(threadSleepTime);

				} else {
					log.info("There are no files available to process, hence thread is going to sleep for "
							+ threadSleepTime);
					System.out.println("There are no files available to process, hence thread is going to sleep for : "
							+ threadSleepTime);
					Thread.sleep(threadSleepTime);
				}
			} catch (Exception e) {
				log.info("Error occurred during valiadation", e);
			} finally {
				log.info(
						"********************************  || AADESH_ACH_MANDATE_DEC UTILITY ENDED ||  ***********************************\n");
			}
		}
	}
}
