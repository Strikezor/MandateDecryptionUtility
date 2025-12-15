package com.tcs.sbi.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Properties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.tcs.sbi.launcher.MandateLauncher;

public class MandateDecProperties {
	public static final Logger log = LogManager.getLogger(MandateLauncher.class);
//	E:\Akshay\MandateFilesStructure
	private static final String PROPERTIES_FILE = "E:\\MandateDecryptionUtility\\MandateDecryptionFilesStructure\\PROPERTY_FILE\\MandateDecProperties.properties";
//	private static final String PROPERTIES_FILE = new File("MandateDecryptionUtility/MandateDecryptionFilesStructure\\PROPERTY_FILE\\ACHMandateDecProperties.properties").getAbsolutePath();
	
	private static MandateDecProperties instance = new MandateDecProperties();
	private String propertyValue = null;
	Properties prop;
	
	InputStream bisCM = null;
	
	private MandateDecProperties() {
		loadProperties();
	}
	
	@Override
	protected void finalize() throws Throwable {
		super.finalize();
		unloadProperties();
	}
	
	private void unloadProperties() {
		log.info("Entering Method.");
		try {
			bisCM.close();
		}
		catch (Exception e) {
			log.error("Error in unloadProperties");
		}
		log.info("Exiting Method.");
	}
	
	private void loadProperties() {
		log.info("Entering Method.");
		
		try {
			bisCM = new FileInputStream(PROPERTIES_FILE);
		}
		catch (FileNotFoundException e1) {
			throw new RuntimeException(e1);
		}
		prop = new Properties();
		try {
			prop.load(bisCM);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		log.info("Exiting method.");
	}
	
	public String getProperty(String key) {
		propertyValue = prop.getProperty(key);
		if (null == propertyValue) {
			throw new RuntimeException("Missing the value of the key " + key + " in .properties file");
		}
		return propertyValue;
	}
	
	public static MandateDecProperties getInstance() {
		if (instance == null) {
			instance = new MandateDecProperties();
		}
		return instance;
	}
}
