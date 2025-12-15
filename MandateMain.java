package com.tcs.sbi.main;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.HashMap;
import java.util.stream.Stream;

import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.tcs.sbi.constants.ErrorConstants;
import com.tcs.sbi.launcher.MandateLauncher;
import com.tcs.sbi.util.MandateUtility;

public class MandateMain implements Runnable {

	public String zipFilepath;
	public String DestDir;

	public MandateMain(String zipFilepath, String destDir) {
		super();
		this.zipFilepath = zipFilepath;
		DestDir = destDir;
	}

	int testCounter = 0;
	private ArrayList<String> fileList = new ArrayList<String>();
	String folder = new String();
	int fnum;
	String fpno;
	private String fileName;

	public MandateMain(ArrayList<String> fileList, String folderName, String fileName) {
		super();
		this.fileList = fileList;
		// this.c = c;
		this.folder = folderName;
		this.fileName = fileName;
	}

	private static final Logger log = LogManager.getLogger(MandateLauncher.class);

	public void run() {
		try {
			FileWriter fstream;
			Calendar cal = Calendar.getInstance();
			int dTm = 0;
			cal.add(Calendar.DATE, dTm);
			String currMonth = "";
			String currentDate = "";
			int calMonth = cal.get(Calendar.MONTH) + 1;
			int calYear = cal.get(Calendar.YEAR);
			int calDate = cal.get(Calendar.DATE);
			int maxDays = 0;
			if (calMonth == 13) {
				calMonth = 1;
			}
			currMonth = calMonth + "";
			if (currMonth.length() == 1) {
				currMonth = "0" + calMonth;
			}
			if (calYear % 4 == 0) {
				maxDays = MandateUtility.returnMaxDays(calMonth);
				if (calMonth == 2) {
					maxDays = 29;
				}
			} else {
				maxDays = MandateUtility.returnMaxDays(calMonth);

			}
			currentDate = (calDate) + "";
			if (Integer.parseInt(currentDate.trim()) <= maxDays) {
				if ((currentDate).length() == 1) {
					currentDate = "0" + (calDate);
				} else {
				}
			}

			File backupCreatePath = new File(MandateLauncher.getBackUpPath() + File.separator + "CREATE"
					+ File.separator + currentDate + currMonth + calYear);
			if (!backupCreatePath.exists()) {
				boolean created = backupCreatePath.mkdirs();
				if (!created) {
					throw new IOException("Failed to create backup directory: " + backupCreatePath.getAbsolutePath());
				}
			}
			File backupDecryptedCreatePath = new File(MandateLauncher.getDecryptedBackupPath() + File.separator
					+ "CREATE" + File.separator + currentDate + currMonth + calYear);
			if (!backupDecryptedCreatePath.exists()) {
				boolean created = backupDecryptedCreatePath.mkdirs();
				if (!created) {
					throw new IOException(
							"Failed to create backup directory: " + backupDecryptedCreatePath.getAbsolutePath());
				}
			}
			File backupAmendPath = new File(MandateLauncher.getBackUpPath() + File.separator + "AMEND" + File.separator
					+ currentDate + currMonth + calYear);
			if (!backupAmendPath.exists()) {
				boolean created = backupAmendPath.mkdirs();
				if (!created) {
					throw new IOException("Failed to create backup directory: " + backupAmendPath.getAbsolutePath());
				}
			}
			File backupDecryptedAmendPath = new File(MandateLauncher.getDecryptedBackupPath() + File.separator + "AMEND"
					+ File.separator + currentDate + currMonth + calYear);
			if (!backupDecryptedAmendPath.exists()) {
				boolean created = backupDecryptedAmendPath.mkdirs();
				if (!created) {
					throw new IOException(
							"Failed to create backup directory: " + backupDecryptedAmendPath.getAbsolutePath());
				}
			}
			File backupCancelPath = new File(MandateLauncher.getBackUpPath() + File.separator + "CANCEL"
					+ File.separator + currentDate + currMonth + calYear);
			if (!backupCancelPath.exists()) {
				boolean created = backupCancelPath.mkdirs();
				if (!created) {
					throw new IOException("Failed to create backup directory: " + backupCancelPath.getAbsolutePath());
				}
			}
			File backupDecryptedCancelPath = new File(MandateLauncher.getDecryptedBackupPath() + File.separator
					+ "CANCEL" + File.separator + currentDate + currMonth + calYear);
			if (!backupDecryptedCancelPath.exists()) {
				boolean created = backupDecryptedCancelPath.mkdirs();
				if (!created) {
					throw new IOException(
							"Failed to create backup directory: " + backupDecryptedCancelPath.getAbsolutePath());
				}
			}

			String Fullpath = MandateLauncher.getSourcePath();
			boolean issignedverify = false;
			boolean isXMLContentReadable = false;
			InputStream SourceFileInputStream;
			HashMap<String, Object> decdmap = new HashMap<String, Object>();
			HashMap<String, String> DecryptedFileMap = null;
			String Orgcontent = null;
			byte[] decodorginalcontent;
			String[] Xmlsepratedcontent;
			boolean dbupdate = false;
			int noofrecords = 0;
			boolean isFilePGPEncrypted;
			boolean isSigned;
			String decfilename = null;
			boolean finalDecryptionStatus = false;

			File folder = new File(zipFilepath);
			File[] files = folder.listFiles();

			boolean isunzipped = false;
			boolean isDecrypted = false;

			if (files != null && files.length > 0) {
				for (File file : files) {
					log.info(
							"------------------------------- New File picked up for Decryption and Unsigning Processing -------------------------------\n");

					if (MandateUtility.typeValidation(file)) {
						if (MandateUtility.extensionValidation(file)) {
							try {
								String referenceNumber = MandateUtility.generateReferenceNumber();
								log.info("File to be processed is :" + file.getName() + " against reference number : "
										+ referenceNumber);

								decdmap.put("ReferenceNumber", referenceNumber);
								decdmap.put("FileName", file);
								decdmap.put("fileCopiedTime", MandateUtility.getTimestamp());

								SourceFileInputStream = new BufferedInputStream(
										new FileInputStream(file.getAbsolutePath()));
//								encryption code start

//								checking if file is encrypted 
								isFilePGPEncrypted = MandateUtility.isPGPEncrypted(file.getAbsolutePath());
								if (isFilePGPEncrypted) {
									SourceFileInputStream = new BufferedInputStream(
											new FileInputStream(file.getAbsolutePath()));
									DecryptedFileMap = MandateUtility.rsaDecryptFile(SourceFileInputStream,
											MandateLauncher.getPgpPrivKey(), file.getName(),
											MandateLauncher.getDecFilePath());
									SourceFileInputStream.close();
									if (!DecryptedFileMap.containsKey("Error")) {
										if (!DecryptedFileMap.containsKey("ERROR")) {
											log.info("File is successfully decrypted and moved to path: "
													+ MandateLauncher.getDecFilePath() + "for reference number "
													+ referenceNumber);

											decdmap.put("Status", ErrorConstants.DECRYPTION_SUCCESS.toString());
											decdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
											decdmap.put("EncryptionType", ErrorConstants.ENCRYPTED_FILE.toString());
											File decryptedFile = Paths.get(
													MandateLauncher.getDecFilePath() + File.separator + file.getName())
													.toFile();
											decfilename = MandateUtility.readXMLContent(file);
											if (decfilename != null) {
												log.info("The XML Content of the file is read");
												Xmlsepratedcontent = MandateUtility.extractalldata(decfilename);
												if (Xmlsepratedcontent.length != 0) {
													log.info("The data extraction of the file is Successful");
													try {
														X509Certificate receivedCert = MandateUtility
																.getX509Certificate(Base64.getDecoder()
																		.decode(Xmlsepratedcontent[2]));
														byte[] decodedBytes = Base64.getDecoder()
																.decode(Xmlsepratedcontent[2]);
														String outputCertFile = new File(
																MandateLauncher.getCheckingCertPath())
																.getAbsolutePath();
														Path outputPath = Paths.get(outputCertFile);
														Files.write(outputPath, decodedBytes);
														issignedverify = MandateUtility.verifysign(
																Xmlsepratedcontent[1], receivedCert,
																Xmlsepratedcontent[0]);
													} catch (Exception e) {
														log.info("Sign Verification Failed: " + e);
													}
//											Unsigning code end
//											unzipping code begin 
													if (issignedverify) {
														decdmap.put("Status",
																ErrorConstants.SIGN_VERIFY_SUCCESS.toString());
														decdmap.put("statusDEC",
																ErrorConstants.SIGN_VERIFY_SUCCESS.name().toString());
														decdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
														log.info("Sign Verification for the file is Successful");
														decodorginalcontent = Base64.getDecoder()
																.decode(Xmlsepratedcontent[0]);
														String filename = file.getName().substring(0,
																file.getName().lastIndexOf('.'));
														finalDecryptionStatus = MandateUtility.unzipfrombytes(filename,
																decodorginalcontent);

//											unzipping code end
														if (finalDecryptionStatus) {
															if(file.getName().contains("AMEND")) {
																MandateUtility.copyFolder(
																		Paths.get(
																				MandateLauncher.getDestDir() + File.separator
																				+ filename),
																		Paths.get(backupDecryptedAmendPath + File.separator
																				+ filename));
															} else if(file.getName().contains("CANCEL")) {
																MandateUtility.copyFolder(
																		Paths.get(
																				MandateLauncher.getDestDir() + File.separator
																				+ filename),
																		Paths.get(backupDecryptedCancelPath + File.separator
																				+ filename));
															} else if(file.getName().contains("CREATE")) {
																MandateUtility.copyFolder(
																		Paths.get(
																				MandateLauncher.getDestDir() + File.separator
																				+ filename),
																		Paths.get(backupDecryptedCreatePath + File.separator
																				+ filename));
															}
															log.info(
																	"File is Successfully decrypted and moved to path : "
																			+ MandateLauncher.getBackUpPath());
															decdmap.put("statusDEC",
																	ErrorConstants.PROCESS_COMPLETED.name().toString());
															decdmap.put("Status",
																	ErrorConstants.PROCESS_COMPLETED.toString());
															decdmap.put("lastUpdatedtime",
																	MandateUtility.getTimestamp());
//																	System.out.println("Successfully decrypted and moved to path : " + MandateLauncher.getBackUpPath());

															String filePath = MandateLauncher.getDestDir()
																	+ File.separator + filename;
															File FileList = new File(filePath);
															File[] listOfFiles = FileList.listFiles();

															try {
																for (File curr : listOfFiles) {
																	if (curr.getName().contains(".tiff")
																			|| curr.getName().contains(".tif")
																			|| curr.getName().contains(".jpg")
																			|| curr.getName().contains(".jpeg")) {
																		Files.move(curr.getAbsoluteFile().toPath(),
																				Paths.get(MandateLauncher.getImagePath()
																						+ File.separator
																						+ curr.getName()),
																				StandardCopyOption.REPLACE_EXISTING);
																	}
																}
															} catch (Exception e) {
																System.out.println(e);
															}

//																	System.out.println(ACHMandateLauncher.getBackUpPath() +"    " +file.getName()+"   "+Fullpath);
															if (SourceFileInputStream != null) {
																SourceFileInputStream.close();
															}
															if (filename.contains("-CREATE-")) {
																Files.move(
																		Paths.get(Fullpath + File.separator
																				+ file.getName()),
																		Paths.get(backupCreatePath + File.separator
																				+ file.getName()),
																		StandardCopyOption.REPLACE_EXISTING);
															} else if (filename.contains("-AMEND-")) {
																Files.move(
																		Paths.get(Fullpath + File.separator
																				+ file.getName()),
																		Paths.get(backupAmendPath + File.separator
																				+ file.getName()),
																		StandardCopyOption.REPLACE_EXISTING);
															} else if (fileName.contains("-CANCEL-")) {
																Files.move(
																		Paths.get(Fullpath + File.separator
																				+ file.getName()),
																		Paths.get(backupCancelPath + File.separator
																				+ file.getName()),
																		StandardCopyOption.REPLACE_EXISTING);
															}
														} else {
															log.info("File Decryption error, Moved to path : "
																	+ MandateLauncher.getDecryptionFailedPath());
															decdmap.put("Status",
																	ErrorConstants.UNZIP_FAILURE.toString());
															decdmap.put("statusDEC", ErrorConstants.UNZIP_FAILURE
																	.name().toString());
															decdmap.put("lastUpdatedtime",
																	MandateUtility.getTimestamp());
															Files.move(
																	Paths.get(
																			Fullpath + File.separator + file.getName()),
																	Paths.get(MandateLauncher.getDecryptionFailedPath()
																			+ File.separator + file.getName())
																			.normalize(),
																	StandardCopyOption.REPLACE_EXISTING);
															System.out.println("Decryption Error");
														}
													} else {
														log.info("The sign was not verified, hence moved to path : "
																+ MandateLauncher.getSignNotVerifiedPath());
														decdmap.put("Status",
																ErrorConstants.SIGN_VERIFY_FAILURE.toString());
														decdmap.put("statusDEC",
																ErrorConstants.SIGN_VERIFY_FAILURE.name().toString());
														decdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
														if (SourceFileInputStream != null) {
															SourceFileInputStream.close();
														}
														Files.move(
																Paths.get(Fullpath + File.separator + file.getName()),
																Paths.get(MandateLauncher.getSignNotVerifiedPath()
																		+ File.separator + file.getName()).normalize(),
																StandardCopyOption.REPLACE_EXISTING);
														System.out.println("sign not verified");
													}
												} else {
													log.info(
															"The data extraction was unsuccessful, hence moved to path : "
																	+ MandateLauncher.getDataExtractionFailedPath());
													if (SourceFileInputStream != null) {
														SourceFileInputStream.close();
													}
													Files.move(Paths.get(Fullpath + File.separator + file.getName()),
															Paths.get(MandateLauncher.getDataExtractionFailedPath()
																	+ File.separator + file.getName()).normalize(),
															StandardCopyOption.REPLACE_EXISTING);
													System.out.print("Extract data failed");
												}
											} 
										} else {
											System.out.println("Error while decrypting the file");
											log.info("Error while decrypting the file");
											decdmap.put("Status",
													ErrorConstants.DECRYPTION_FAILURE.toString());
											decdmap.put("statusDEC",
													ErrorConstants.DECRYPTION_FAILURE.name().toString());
											decdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
										}
									}
								} else {
									isSigned = MandateUtility.isSignedFile(file.getAbsolutePath());
									if (isSigned) {
										decfilename = MandateUtility.readXMLContent(file);
										if (decfilename != null) {
											log.info("The XML Content of the file is read");
											Xmlsepratedcontent = MandateUtility.extractalldata(decfilename);
											if (Xmlsepratedcontent.length != 0) {
												log.info("The data extraction of the file is Successful");
												try {
													X509Certificate receivedCert = MandateUtility.getX509Certificate(
															Base64.getDecoder().decode(Xmlsepratedcontent[2]));
													byte[] decodedBytes = Base64.getDecoder()
															.decode(Xmlsepratedcontent[2]);
													String outputCertFile = new File(
															MandateLauncher.getCheckingCertPath()).getAbsolutePath();
													Path outputPath = Paths.get(outputCertFile);
													Files.write(outputPath, decodedBytes);
													issignedverify = MandateUtility.verifysign(Xmlsepratedcontent[1],
															receivedCert, Xmlsepratedcontent[0]);
												} catch (Exception e) {
													log.info("Sign Verification Failed: " + e);
												}
//										Unsigning code end
//										unzipping code begin
												if (issignedverify) {
													decdmap.put("Status",
															ErrorConstants.SIGN_VERIFY_SUCCESS.toString());
													decdmap.put("statusDEC",
															ErrorConstants.SIGN_VERIFY_SUCCESS.name().toString());
													decdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
													log.info("Sign Verification for the file is Successful");
													decodorginalcontent = Base64.getDecoder()
															.decode(Xmlsepratedcontent[0]);
													String filename = file.getName().substring(0,
															file.getName().lastIndexOf('.'));
													finalDecryptionStatus = MandateUtility.unzipfrombytes(filename,
															decodorginalcontent);

//										unzipping code end
													if (finalDecryptionStatus) {
														if(file.getName().contains("AMEND")) {
															MandateUtility.copyFolder(
																	Paths.get(
																			MandateLauncher.getDestDir() + File.separator
																			+ filename),
																	Paths.get(backupDecryptedAmendPath + File.separator
																			+ filename));
														} else if(file.getName().contains("CANCEL")) {
															MandateUtility.copyFolder(
																	Paths.get(
																			MandateLauncher.getDestDir() + File.separator
																			+ filename),
																	Paths.get(backupDecryptedCancelPath + File.separator
																			+ filename));
														} else if(file.getName().contains("CREATE")) {
															MandateUtility.copyFolder(
																	Paths.get(
																			MandateLauncher.getDestDir() + File.separator
																			+ filename),
																	Paths.get(backupDecryptedCreatePath + File.separator
																			+ filename));
														}
														log.info("File is Successfully decrypted and moved to path : "
																+ MandateLauncher.getBackUpPath());
														decdmap.put("statusDEC",
																ErrorConstants.PROCESS_COMPLETED.name().toString());
														decdmap.put("Status",
																ErrorConstants.PROCESS_COMPLETED.toString());
														decdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
//																System.out.println("Successfully decrypted and moved to path : " + MandateLauncher.getBackUpPath());

														String filePath = MandateLauncher.getDestDir() + File.separator
																+ filename;
														File FileList = new File(filePath);
														File[] listOfFiles = FileList.listFiles();

														try {
															for (File curr : listOfFiles) {
																if (curr.getName().contains(".tiff")
																		|| curr.getName().contains(".tif")
																		|| curr.getName().contains(".jpg")
																		|| curr.getName().contains(".jpeg")) {
																	Files.move(curr.getAbsoluteFile().toPath(),
																			Paths.get(MandateLauncher.getImagePath()
																					+ File.separator + curr.getName()),
																			StandardCopyOption.REPLACE_EXISTING);
																}
															}
														} catch (Exception e) {
															System.out.println(e);
														}

//																System.out.println(ACHMandateLauncher.getBackUpPath() +"    " +file.getName()+"   "+Fullpath);
														if (SourceFileInputStream != null) {
															SourceFileInputStream.close();
														}
														if (filename.contains("-CREATE-")) {
															Files.move(
																	Paths.get(
																			Fullpath + File.separator + file.getName()),
																	Paths.get(backupCreatePath + File.separator
																			+ file.getName()),
																	StandardCopyOption.REPLACE_EXISTING);
														} else if (filename.contains("-AMEND-")) {
															Files.move(
																	Paths.get(
																			Fullpath + File.separator + file.getName()),
																	Paths.get(backupAmendPath + File.separator
																			+ file.getName()),
																	StandardCopyOption.REPLACE_EXISTING);
														} else if (filename.contains("-CANCEL-")) {
															Files.move(
																	Paths.get(
																			Fullpath + File.separator + file.getName()),
																	Paths.get(backupCancelPath + File.separator
																			+ file.getName()),
																	StandardCopyOption.REPLACE_EXISTING);
														}
													} else {
														log.info("File Unzipping error, Moved to path : "
																+ MandateLauncher.getDecryptionFailedPath());
														decdmap.put("Status", ErrorConstants.UNZIP_FAILURE.toString());
														decdmap.put("statusDEC",
																ErrorConstants.UNZIP_FAILURE.name().toString());
														decdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
														Files.move(
																Paths.get(Fullpath + File.separator + file.getName()),
																Paths.get(MandateLauncher.getDecryptionFailedPath()
																		+ File.separator + file.getName()).normalize(),
																StandardCopyOption.REPLACE_EXISTING);
														System.out.println("Decryption Error");
													}
												} else {
													log.info("The sign was not verified, hence moved to path : "
															+ MandateLauncher.getSignNotVerifiedPath());
													decdmap.put("Status",
															ErrorConstants.SIGN_VERIFY_FAILURE.toString());
													decdmap.put("statusDEC",
															ErrorConstants.SIGN_VERIFY_FAILURE.name().toString());
													decdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
													if (SourceFileInputStream != null) {
														SourceFileInputStream.close();
													}
													Files.move(Paths.get(Fullpath + File.separator + file.getName()),
															Paths.get(MandateLauncher.getSignNotVerifiedPath()
																	+ File.separator + file.getName()).normalize(),
															StandardCopyOption.REPLACE_EXISTING);
													System.out.println("sign not verified");
												}
											}
										}
									} else {
										log.info("File Decryption error, Moved to path : "
												+ MandateLauncher.getDecryptionFailedPath());

										decdmap.put("Status", ErrorConstants.DECRYPTION_FAILURE.toString());
										decdmap.put("statusDEC", ErrorConstants.DECRYPTION_FAILURE.name().toString());
										decdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());

										Files.move(Paths.get(file.getAbsolutePath()),
												Paths.get(MandateLauncher.getDecryptionFailedPath() + File.separator
														+ file.getName()).normalize(),
												StandardCopyOption.REPLACE_EXISTING);
										System.out.println("Decryption Error");
									}
								}
							} catch (Exception e) {
								System.out.println(e);
							}
						} else {
							log.info(file.getName() + " is not a ZIP file, hence moved to path : "
									+ MandateLauncher.getNotaZIPPath());
							Files.move(Paths.get(Fullpath + File.separator + file.getName()),
									Paths.get(MandateLauncher.getNotaZIPPath() + File.separator + file.getName())
											.normalize(),
									StandardCopyOption.REPLACE_EXISTING);
							System.out.println(file.getName() + " is not a Zip file");
						}
					} else {
						log.info(file.getName() + " is not a file");
						System.out.println(file.getName() + " is not a file");
					}
				}
			}
		} catch (Exception e) {
			log.info("Error : " + e);
		} finally {
			log.info("********** File reading and processing ends here! ****************");
		}
	}

}
