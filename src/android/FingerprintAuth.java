package android;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Locale;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.FragmentTransaction;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.hardware.fingerprint.FingerprintManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import ch.qos.logback.classic.Logger;

@TargetApi(23)
@SuppressWarnings({"java:S112", "java:S2147", "java:S1192"})
public class FingerprintAuth extends CordovaPlugin {
	private Logger logger;
	
    public static final String TAG = "FingerprintAuth";
    public String packageName;

    private static final String DIALOG_FRAGMENT_TAG = "FpAuthDialog";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String FINGERPRINT_PREF_IV = "aes_iv";
    private static final int PERMISSIONS_REQUEST_FINGERPRINT = 346437;
    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;
    private static final String CREDENTIAL_DELIMITER = "|:|";

    public Context mContext;
    public Activity mActivity;
    public KeyguardManager mKeyguardManager;
    public FingerprintAuthenticationDialogFragment mFragment;
    public KeyStore mKeyStore;
    public KeyGenerator mKeyGenerator;
    public Cipher mCipher;
    private FingerprintManager mFingerPrintManager;

    public CallbackContext mCallbackContext;
    public PluginResult mPluginResult;

    public enum PluginAction {
        AVAILABILITY,
        ENCRYPT,
        DECRYPT,
        DELETE,
        DISMISS
    }

    public enum PluginError {
        BAD_PADDING_EXCEPTION,
        CERTIFICATE_EXCEPTION,
        FINGERPRINT_CANCELLED,
        FINGERPRINT_DATA_NOT_DELETED,
        FINGERPRINT_ERROR,
        FINGERPRINT_NOT_AVAILABLE,
        FINGERPRINT_PERMISSION_DENIED,
        FINGERPRINT_PERMISSION_DENIED_SHOW_REQUEST,
        ILLEGAL_BLOCK_SIZE_EXCEPTION,
        INIT_CIPHER_FAILED,
        INVALID_ALGORITHM_PARAMETER_EXCEPTION,
        IO_EXCEPTION,
        JSON_EXCEPTION,
        MINIMUM_SDK,
        MISSING_ACTION_PARAMETERS,
        MISSING_PARAMETERS,
        NO_SUCH_ALGORITHM_EXCEPTION,
        SECURITY_EXCEPTION,
        FRAGMENT_NOT_EXIST
    }

    public PluginAction mAction;

    /**
     * Alias for our key in the Android Key Store
     */
    private String mClientId;
    /**
     * Used to encrypt token
     */
    private String mUsername = "";
    private String mClientSecret;
    private boolean mCipherModeCrypt = true;

    /**
     * Options
     */
    public boolean mDisableBackup = false;
    public int mMaxAttempts = 6;  // one more than the device default to prevent a 2nd callback
    private String mLangCode = "en_US";
    private boolean mUserAuthRequired = false;
    public String mDialogTitle;
    public String mDialogMessage;
    public String mDialogHint;
    public boolean mEncryptNoAuth = false;


    /**
     * Sets the context of the Command. This can then be used to do things like
     * get file paths associated with the Activity.
     *
     * @param cordova The context of the main Activity.
     * @param webView The CordovaWebView Cordova is running in.
     */
    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
    	this.logger = new LogToFile().configureLogger(cordova.getActivity().getExternalFilesDir(null).getAbsolutePath() + "/logs");
    	
        super.initialize(cordova, webView);
        
        logger.debug("Init FingerprintAuth");

        packageName = cordova.getActivity().getApplicationContext().getPackageName();
        mPluginResult = new PluginResult(PluginResult.Status.NO_RESULT);
        mActivity = cordova.getActivity();
        mContext = cordova.getActivity().getApplicationContext();

        if (android.os.Build.VERSION.SDK_INT < 21) {
        	logger.warn("Version SDK < 21 exit!");
            return;
        }

        mKeyguardManager = cordova.getActivity().getSystemService(KeyguardManager.class);
        
        if (android.os.Build.VERSION.SDK_INT > 23) {
        	logger.info("Version SDK > 21 extract FingerprintManager");
        	
	        mFingerPrintManager = cordova.getActivity().getApplicationContext().getSystemService(FingerprintManager.class);
        }

        try {
            mKeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
            mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            
        } catch (Exception e) {
        	logger.error("Failed to get an instance of KeyGenerator,KeyStore", e);
            throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
        }

        try {
            mCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (Exception e) {
        	logger.error("Failed to get an instance of Cipher", e);
        	throw new RuntimeException("Failed to get an instance of Cipher", e);
        }
    }

    /**
     * Executes the request and returns PluginResult.
     *
     * @param action          The action to execute.
     * @param args            JSONArray of arguments for the plugin.
     * @param callbackContext The callback id used when calling back into JavaScript.
     * @return A PluginResult object with a status and message.
     */
    public boolean execute(final String action, JSONArray args, final CallbackContext callbackContext) throws JSONException {
    	
    	try {
	        mCallbackContext = callbackContext;
	
	        logger.debug("FingerprintAuth action: {}", action);
	        
	        if (action.equals("availability")) {
	            mAction = PluginAction.AVAILABILITY;
	        } else if (action.equals("encrypt")) {
	            mAction = PluginAction.ENCRYPT;
	            mCipherModeCrypt = true;
	        } else if (action.equals("decrypt")) {
	            mAction = PluginAction.DECRYPT;
	            mCipherModeCrypt = false;
	        } else if (action.equals("delete")) {
	            mAction = PluginAction.DELETE;
	        } else if (action.equals("dismiss")) {
	            mAction = PluginAction.DISMISS;
	        } else {
	        	returnError(callbackContext, "No action", null, null);
	        	return true;
	        }
	
			final JSONObject argObject = args.getJSONObject(0);
	
			if (mAction != PluginAction.AVAILABILITY && mAction != PluginAction.DISMISS) {
	
				if (!argObject.has("clientId")) {
					returnError(callbackContext, "Missing required parameters.", PluginError.MISSING_PARAMETERS.name(), null);
					return true;
				}
	
				mClientId = argObject.getString("clientId");
	
				if (argObject.has("username")) {
					mUsername = argObject.getString("username");
				}
			}
	
			switch (mAction) {
				case AVAILABILITY:
					if (android.os.Build.VERSION.SDK_INT > 23 && !cordova.hasPermission(Manifest.permission.USE_FINGERPRINT)) {
						logger.debug("SDK > 23 but not permission");
		
						cordova.requestPermission(this, PERMISSIONS_REQUEST_FINGERPRINT, Manifest.permission.USE_FINGERPRINT);
					} else {
						sendAvailabilityResult();
					}
					return true;
				case ENCRYPT:
				case DECRYPT:
					boolean missingParam = false;
					mEncryptNoAuth = false;
		
					if (PluginAction.ENCRYPT.equals(mAction)) {
		
						String password = argObject.has("password") ? argObject.getString("password") : "";
		
						mClientSecret = mClientId + mUsername + CREDENTIAL_DELIMITER + password;
		
						if (argObject.has("encryptNoAuth")) {
							mEncryptNoAuth = argObject.getBoolean("encryptNoAuth");
						}
					} else if (PluginAction.DECRYPT.equals(mAction)) {
		
						if (argObject.has("token")) {
							mClientSecret = argObject.getString("token");
						} else {
							missingParam = true;
						}
					}
		
					if (missingParam) {
						returnError(callbackContext, "Missing required parameters for specified action.", PluginError.MISSING_ACTION_PARAMETERS.name(), null);
						return true;
					}
		
					if (argObject.has("disableBackup")) {
						mDisableBackup = argObject.getBoolean("disableBackup");
					}
					if (argObject.has("locale")) {
						mLangCode = argObject.getString("locale");
						Log.d(TAG, "Change language to locale: " + mLangCode);
					}
					if (argObject.has("maxAttempts")) {
						int maxAttempts = argObject.getInt("maxAttempts");
						if (maxAttempts < 5) {
							mMaxAttempts = maxAttempts;
						}
					}
					if (argObject.has("userAuthRequired")) {
						mUserAuthRequired = argObject.getBoolean("userAuthRequired");
					}
					if (argObject.has("dialogTitle")) {
						mDialogTitle = argObject.getString("dialogTitle");
					}
					if (argObject.has("dialogMessage")) {
						mDialogMessage = argObject.getString("dialogMessage");
					}
					if (argObject.has("dialogHint")) {
						mDialogHint = argObject.getString("dialogHint");
					}
		
					// Set language
					Resources res = cordova.getActivity().getResources();
					// Change locale settings in the app.
					Configuration conf = res.getConfiguration();
		
					// A length of 5 entales a region specific locale string, ex: zh_HK.
					// The two argument Locale constructor signature must be used in that case.
					if (mLangCode.length() == 5) {
						conf.locale = new Locale(mLangCode.substring(0, 2).toLowerCase(), mLangCode.substring(mLangCode.length() - 2).toUpperCase());
					} else {
						conf.locale = new Locale(mLangCode.toLowerCase());
					}
		
					res.updateConfiguration(conf, res.getDisplayMetrics());
		
					SecretKey key = getSecretKey();
					if (key == null && createKey()) {
						key = getSecretKey();
					}
		
					if (key == null) {
						mCallbackContext.sendPluginResult(mPluginResult);
					} else {
						if (mEncryptNoAuth) {
							onAuthenticated(false, null);
		
						} else {
		
							if (isFingerprintAuthAvailable()) {
		
								cordova.getActivity().runOnUiThread(new Runnable() {
									public void run() {
										// Set up the crypto object for later. The object will be authenticated by use
										// of the fingerprint.
										mFragment = new FingerprintAuthenticationDialogFragment();
										mFragment.setFingerprintAuth(FingerprintAuth.this);
										
										if (initCipher()) {
											mFragment.setCancelable(false);
											// Show the fingerprint dialog. The user has the option to use the fingerprint
											// with
											// crypto, or you can fall back to using a server-side verified password.
											mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
											FragmentTransaction transaction = cordova.getActivity().getFragmentManager().beginTransaction();
											transaction.add(mFragment, DIALOG_FRAGMENT_TAG);
											transaction.commitAllowingStateLoss();
										} else {
											if (!mDisableBackup) {
												// This happens if the lock screen has been disabled or or a fingerprint got
												// enrolled. Thus show the dialog to authenticate with their password
												mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
												mFragment.setStage(FingerprintAuthenticationDialogFragment.Stage.NEW_FINGERPRINT_ENROLLED);
												FragmentTransaction transaction = cordova.getActivity().getFragmentManager().beginTransaction();
												transaction.add(mFragment, DIALOG_FRAGMENT_TAG);
												transaction.commitAllowingStateLoss();
											} else {
												FingerprintAuth.this.returnError(callbackContext, "Failed to init Cipher and backup disabled.", PluginError.INIT_CIPHER_FAILED.name(), null);
											}
										}
									}
								});
								mPluginResult.setKeepCallback(true);
		
							} else if (isLockScreen()) {
								logger.debug("Use backup");
		
								showAuthenticationScreen();
		
							} else {
								returnError(callbackContext, "Fingerprint authentication not available", PluginError.FINGERPRINT_NOT_AVAILABLE.name(), null);
							}
						}
					}
		
					return true;
		
				case DELETE:
					boolean ivDeleted = false;
					boolean secretKeyDeleted = false;
					try {
						mKeyStore.load(null);
						mKeyStore.deleteEntry(mClientId);
						secretKeyDeleted = true;
						ivDeleted = deleteIV();
					} catch (Exception e) {
						returnError(callbackContext, "Error while deleting SecretKey.", null, e);
					}
		
					if (ivDeleted && secretKeyDeleted) {
						mPluginResult = new PluginResult(PluginResult.Status.OK);
						mCallbackContext.success();
					} else {
						returnError(callbackContext, "Error while deleting Fingerprint data.", PluginError.FINGERPRINT_DATA_NOT_DELETED.name(), null);
					}
					mCallbackContext.sendPluginResult(mPluginResult);
					return true;
		
				case DISMISS:
					if (null != mFragment) {
						cordova.getActivity().getFragmentManager().beginTransaction().remove(mFragment).commit();
		
						mPluginResult = new PluginResult(PluginResult.Status.OK);
						mCallbackContext.success("Fragment dismissed");
						mCallbackContext.sendPluginResult(mPluginResult);
					} else {
						returnError(callbackContext, "Fragment not exist", PluginError.FRAGMENT_NOT_EXIST.name(), null);
					}
					return true;
				}
			
    	} catch (Exception e) {
    		returnError(callbackContext, "Generic error", null, null);
		}
    	
    	return false;
	}
    
	private void returnError(CallbackContext callbackContext, String message, String code, Exception e) {
        logger.error(message, e);
        
        PluginResult pluginResult = new PluginResult(PluginResult.Status.ERROR);
        callbackContext.error(code);
        callbackContext.sendPluginResult(pluginResult);
	}

	/*********************************************************************
	 * Backup for older devices without fingerprint hardware/software
	 **********************************************************************/
	private boolean isLockScreen() {
		return mKeyguardManager.isKeyguardSecure(); 
	}
    
    private boolean isFingerprintAuthAvailable() throws SecurityException {
    	return isHardwareDetected() && hasEnrolledFingerprints();
    }

    private boolean isAvailable() throws SecurityException {
    	return isFingerprintAuthAvailable() || isLockScreen();
    }

    private boolean isHardwareDetected() {
    	return android.os.Build.VERSION.SDK_INT > 23 && null != mFingerPrintManager && mFingerPrintManager.isHardwareDetected();
    }
    
    private boolean hasEnrolledFingerprints() {
    	return android.os.Build.VERSION.SDK_INT > 23 && null != mFingerPrintManager && mFingerPrintManager.hasEnrolledFingerprints();
    }
    
    private void sendAvailabilityResult() {
        try {
        	JSONObject resultJson = new JSONObject();
        	
            resultJson.put("isAvailable", isAvailable());
            resultJson.put("isHardwareDetected", isHardwareDetected());
            resultJson.put("hasEnrolledFingerprints", hasEnrolledFingerprints());
            
            mPluginResult = new PluginResult(PluginResult.Status.OK);
            mCallbackContext.success(resultJson);
            mCallbackContext.sendPluginResult(mPluginResult);
            
        } catch (Exception e) {
        	returnError(mCallbackContext, "Check Availability", PluginError.FINGERPRINT_ERROR.name(), e);
        } 
    }

    /**
     * @deprecated (when, why, refactoring advice...)
     */
    @Override
    @Deprecated
	public void onRequestPermissionResult(int requestCode, String[] permissions, int[] grantResults) throws JSONException {
		// super.onRequestPermissionsResult(requestCode, permissions, grantResults);

		if (PERMISSIONS_REQUEST_FINGERPRINT == requestCode) {

			// If request is cancelled, the result arrays are empty.
			if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {

				// permission was granted, yay! Do the
				// contacts-related task you need to do.
				sendAvailabilityResult();
			} else {
				returnError(mCallbackContext, "Fingerprint permission denied.", PluginError.FINGERPRINT_PERMISSION_DENIED.name(), null);
			}
		}
	}

    /**
     * Initialize the {@link Cipher} instance with the created key in the {@link #createKey()}
     * method.
     *
     * @return {@code true} if initialization is successful, {@code false} if the lock screen has
     * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
     * the key was generated.
     */
    private boolean initCipher() {
        String errorMessage = "";
        byte[] mCipherIV;

        try {
            SecretKey key = getSecretKey();

            if (mCipherModeCrypt) {
                mCipher.init(Cipher.ENCRYPT_MODE, key);
                mCipherIV = mCipher.getIV();
                setStringPreference(mContext, mClientId + mUsername, FINGERPRINT_PREF_IV, new String(Base64.encode(mCipherIV, Base64.NO_WRAP)));
                
            } else {
				mCipherIV = Base64.decode(getStringPreference(mContext, mClientId + mUsername, FINGERPRINT_PREF_IV), Base64.NO_WRAP);
                IvParameterSpec ivspec = new IvParameterSpec(mCipherIV);
                mCipher.init(Cipher.DECRYPT_MODE, key, ivspec);
            }
            
        } catch (Exception e) {
            logger.error(errorMessage, e);
            return false;
        }
        
        return true;
    }

    public boolean deleteIV() {
        return deleteStringPreference(mContext, mClientId + mUsername, FINGERPRINT_PREF_IV);
    }

    private SecretKey getSecretKey() {
        SecretKey key = null;
        
        try {
            mKeyStore.load(null);
            key = (SecretKey) mKeyStore.getKey(mClientId, null);
            
        } catch (Exception e) {
            logger.error("Error on getSecretKey", e);
        }
        
        return key;
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with fingerprint.
     */
    public boolean createKey() {
        String errorMessage = "";
        String createKeyExceptionErrorPrefix = "Failed to create key: ";
        
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            mKeyStore.load(null);
            
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
            mKeyGenerator.init(new KeyGenParameterSpec.Builder(mClientId,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(mUserAuthRequired)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            
            mKeyGenerator.generateKey();
            
            return true;
            
        } catch (Exception e) {
        	
        	if(e instanceof NoSuchAlgorithmException) {
        		errorMessage = PluginError.NO_SUCH_ALGORITHM_EXCEPTION.name();
        	} else if(e instanceof InvalidAlgorithmParameterException) {
        		errorMessage = PluginError.INVALID_ALGORITHM_PARAMETER_EXCEPTION.name();
        	} else if(e instanceof CertificateException) {
        		errorMessage = PluginError.CERTIFICATE_EXCEPTION.name();
        	} else if(e instanceof IOException) {
        		errorMessage = PluginError.IO_EXCEPTION.name();
        	} else {
        		errorMessage = "Generic error";
        	}
        	
            logger.error(errorMessage, e);
            
            setPluginResultError(errorMessage);
            
            return false;
        } 
    }

    public void onAuthenticated(boolean withFingerprint,
                                       FingerprintManager.AuthenticationResult result) {
        JSONObject resultJson = new JSONObject();
        String errorMessage = "";
        boolean createdResultJson = false;

        try {
            byte[] bytes;
            FingerprintManager.CryptoObject cryptoObject = null;

            if (withFingerprint) {
                resultJson.put("withFingerprint", true);
                cryptoObject = result.getCryptoObject();
            } else {
                resultJson.put("withBackup", true);

                // If failed to init cipher because of InvalidKeyException, create new key
                if (!initCipher()) {
                    createKey();
                }

                if (initCipher()) {
                    cryptoObject = new FingerprintManager.CryptoObject(mCipher);
                }
            }

            if (cryptoObject == null) {
                errorMessage = PluginError.INIT_CIPHER_FAILED.name();
            } else {
                if (mCipherModeCrypt) {
                    bytes = cryptoObject.getCipher().doFinal(mClientSecret.getBytes(StandardCharsets.UTF_8));
                    String encodedBytes = Base64.encodeToString(bytes, Base64.NO_WRAP);
                    resultJson.put("token", encodedBytes);
                } else {
                    bytes = cryptoObject.getCipher().doFinal(Base64.decode(mClientSecret, Base64.NO_WRAP));
                    String credentialString = new String(bytes, StandardCharsets.UTF_8);
                    Pattern pattern = Pattern.compile(Pattern.quote(CREDENTIAL_DELIMITER));
                    String[] credentialArray = pattern.split(credentialString);
                    if (credentialArray.length == 2) {
                        String username = credentialArray[0];
                        String password = credentialArray[1];
                        if (username.equalsIgnoreCase(mClientId + mUsername)) {
                            resultJson.put("password", password);
                        }
                    } else {
                        credentialArray = credentialString.split(":");
                        if (credentialArray.length == 2) {
                            String username = credentialArray[0];
                            String password = credentialArray[1];
                            if (username.equalsIgnoreCase(mClientId + mUsername)) {
                                resultJson.put("password", password);
                            }
                        }
                    }
                }
                createdResultJson = true;
            }
        } catch (BadPaddingException e) {
            logger.error( "Failed to encrypt the data with the generated key:" + " BadPaddingException:  " + e.toString(), e);
            errorMessage = PluginError.BAD_PADDING_EXCEPTION.name();
        } catch (IllegalBlockSizeException e) {
        	logger.error("Failed to encrypt the data with the generated key: " + "IllegalBlockSizeException: " + e.toString(), e);
            errorMessage = PluginError.ILLEGAL_BLOCK_SIZE_EXCEPTION.name();
        } catch (JSONException e) {
        	logger.error("Failed to set resultJson key value pair: " + e.toString(), e);
            errorMessage = PluginError.JSON_EXCEPTION.name();
        }

        if (createdResultJson) {
            mCallbackContext.success(resultJson);
            mPluginResult = new PluginResult(PluginResult.Status.OK);
        } else {
            mCallbackContext.error(errorMessage);
            mPluginResult = new PluginResult(PluginResult.Status.ERROR);
        }
        mCallbackContext.sendPluginResult(mPluginResult);
    }

    public void onCancelled() {
        mCallbackContext.error(PluginError.FINGERPRINT_CANCELLED.name());
    }

    public void onError(CharSequence errString) {
    	logger.error(errString.toString());
    	
        mCallbackContext.error(PluginError.FINGERPRINT_ERROR.name());
    }

    public void setPluginResultError(String errorMessage) {
    	logger.error(errorMessage);
    	
        mCallbackContext.error(errorMessage);
        mPluginResult = new PluginResult(PluginResult.Status.ERROR);
    }

    /**
     * Get a String preference
     *
     * @param context App context
     * @param name    Preference name
     * @param key     Preference key
     * @return Requested preference, if not exist returns null
     */
    public static String getStringPreference(Context context, String name, String key) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE);
        return sharedPreferences.getString(key, null);
    }

    /**
     * Set a String preference
     *
     * @param context App context
     * @param name    Preference name
     * @param key     Preference key
     * @param value   Preference value to be saved
     */
    public static void setStringPreference(Context context, String name, String key, String value) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();

        editor.putString(key, value);
        editor.apply();
    }

    /**
     * Delete a String preference
     *
     * @param context App context
     * @param name    Preference name
     * @param key     Preference key
     * @return Returns true if deleted otherwise false
     */
    public static boolean deleteStringPreference(Context context, String name, String key) {
        SharedPreferences sharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();

        return editor.remove(key).commit();
    }

    private void showAuthenticationScreen() {
        Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(null, null);
        if (intent != null) {
          cordova.setActivityResultCallback(this);
          cordova.getActivity().startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            if (resultCode == Activity.RESULT_OK) {
              onAuthenticated(false, null);
            } else {
              onCancelled();
            }
        }
    }
}
