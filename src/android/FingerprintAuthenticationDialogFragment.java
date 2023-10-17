/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package android;

import android.app.Activity;
import android.app.DialogFragment;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * A dialog which uses fingerprint APIs to authenticate the user, and falls back to password
 * authentication if fingerprint is not available.
 */
public class FingerprintAuthenticationDialogFragment extends DialogFragment
        implements FingerprintUiHelper.Callback {

    private static final String TAG = "FingerprintAuthDialog";
    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;

    private Button mCancelButton;
    private Button mSecondDialogButton;
    private View mFingerprintContent;

    private Stage mStage = Stage.FINGERPRINT;

    private KeyguardManager mKeyguardManager;
    private FingerprintManager.CryptoObject mCryptoObject;
    private FingerprintUiHelper mFingerprintUiHelper;
    FingerprintUiHelper.FingerprintUiHelperBuilder mFingerprintUiHelperBuilder;
	private FingerprintAuth fingerprintAuth;
	
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        setRetainInstance(true);
        setStyle(DialogFragment.STYLE_NO_TITLE, android.R.style.Theme_Material_Light_Dialog);

        mKeyguardManager = (KeyguardManager) getContext().getSystemService(Context.KEYGUARD_SERVICE);
        mFingerprintUiHelperBuilder = new FingerprintUiHelper.FingerprintUiHelperBuilder(
                getContext(), getContext().getSystemService(FingerprintManager.class), fingerprintAuth);

    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        Log.d(TAG, "disableBackup: " + fingerprintAuth.mDisableBackup);

        // Inflate layout
        int fingerprintDialogContainerId = getResources()
                .getIdentifier("fingerprint_dialog_container", "layout",
                		fingerprintAuth.packageName);
        View v = inflater.inflate(fingerprintDialogContainerId, container, false);

        // Set dialog Title
        int fingerprintAuthDialogTitleId = getResources()
                .getIdentifier("fingerprint_auth_dialog_title", "id", fingerprintAuth.packageName);
        TextView dialogTitleTextView = (TextView) v.findViewById(fingerprintAuthDialogTitleId);
        if (null != fingerprintAuth.mDialogTitle) {
            dialogTitleTextView.setText(fingerprintAuth.mDialogTitle);
        }

        // Set dialog message
        int fingerprintDescriptionId = getResources()
                .getIdentifier("fingerprint_description", "id", fingerprintAuth.packageName);
        TextView dialogMessageTextView = (TextView) v.findViewById(fingerprintDescriptionId);
        if (null != fingerprintAuth.mDialogMessage) {
            dialogMessageTextView.setText(fingerprintAuth.mDialogMessage);
        }

        // Set dialog hing
        int fingerprintHintId = getResources()
                .getIdentifier("fingerprint_status", "id", fingerprintAuth.packageName);
        TextView dialogHintTextView = (TextView) v.findViewById(fingerprintHintId);
        if (null != fingerprintAuth.mDialogHint) {
            dialogHintTextView.setText(fingerprintAuth.mDialogHint);
        }

        int cancelButtonId = getResources()
                .getIdentifier("cancel_button", "id", fingerprintAuth.packageName);
        mCancelButton = (Button) v.findViewById(cancelButtonId);
        mCancelButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
            	fingerprintAuth.onCancelled();
                dismissAllowingStateLoss();
            }
        });

        int secondDialogButtonId = getResources()
                .getIdentifier("second_dialog_button", "id", fingerprintAuth.packageName);
        mSecondDialogButton = (Button) v.findViewById(secondDialogButtonId);
        if (fingerprintAuth.mDisableBackup) {
            mSecondDialogButton.setVisibility(View.GONE);
        }
        mSecondDialogButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                goToBackup();
            }
        });
        int fingerprintContainerId = getResources()
                .getIdentifier("fingerprint_container", "id", fingerprintAuth.packageName);
        mFingerprintContent = v.findViewById(fingerprintContainerId);

        int newFingerprintEnrolledDescriptionId = getResources().getIdentifier("new_fingerprint_enrolled_description", "id", fingerprintAuth.packageName);
        int fingerprintIconId = getResources().getIdentifier("fingerprint_icon", "id", fingerprintAuth.packageName);
        int fingerprintStatusId = getResources().getIdentifier("fingerprint_status", "id", fingerprintAuth.packageName);
        
        mFingerprintUiHelper = mFingerprintUiHelperBuilder.build(
                (ImageView) v.findViewById(fingerprintIconId),
                (TextView) v.findViewById(fingerprintStatusId), this);
        updateStage();

        // If fingerprint authentication is not available, switch immediately to the backup
        // (password) screen.
        if (!mFingerprintUiHelper.isFingerprintAuthAvailable()) {
            goToBackup();
        }
        return v;
    }


    @Override
    public void onResume() {
        super.onResume();
        if (mStage == Stage.FINGERPRINT) {
            mFingerprintUiHelper.startListening(mCryptoObject);
        }
    }

    public void setStage(Stage stage) {
        mStage = stage;
    }

    @Override
    public void onPause() {
        super.onPause();
        mFingerprintUiHelper.stopListening();
    }

    /**
     * Sets the crypto object to be passed in when authenticating with fingerprint.
     */
    public void setCryptoObject(FingerprintManager.CryptoObject cryptoObject) {
        mCryptoObject = cryptoObject;
    }

    /**
     * Switches to backup (password) screen. This either can happen when fingerprint is not
     * available or the user chooses to use the password authentication method by pressing the
     * button. This can also happen when the user had too many fingerprint attempts.
     */
    private void goToBackup() {
        mStage = Stage.BACKUP;
        updateStage();
    }

    private void updateStage() {
        int cancelId = getResources()
                .getIdentifier("cancel", "string", fingerprintAuth.packageName);
        switch (mStage) {
            case FINGERPRINT:
                mCancelButton.setText(cancelId);
                int useBackupId = getResources()
                        .getIdentifier("use_backup", "string", fingerprintAuth.packageName);
                mSecondDialogButton.setText(useBackupId);
                mFingerprintContent.setVisibility(View.VISIBLE);
                break;
            case NEW_FINGERPRINT_ENROLLED:
                // Intentional fall through
            case BACKUP:
                if (mStage == Stage.NEW_FINGERPRINT_ENROLLED) {

                }
                if (!mKeyguardManager.isKeyguardSecure()) {
                    // Show a message that the user hasn't set up a lock screen.
                    int secureLockScreenRequiredId = getResources().getIdentifier("secure_lock_screen_required", "string", fingerprintAuth.packageName);
                    Toast.makeText(getContext(),
                            getString(secureLockScreenRequiredId),
                            Toast.LENGTH_LONG).show();
                    return;
                }
                if (fingerprintAuth.mDisableBackup) {
                	fingerprintAuth.onError("backup disabled");
                    return;
                }
                showAuthenticationScreen();
                break;
        }
    }

    private void showAuthenticationScreen() {
        // Create the Confirm Credentials screen. You can customize the title and description. Or
        // we will provide a generic one for you if you leave it null
        Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(null, null);
        if (intent != null) {
            startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            getActivity();
			// Challenge completed, proceed with using cipher
            if (resultCode == Activity.RESULT_OK) {
            	fingerprintAuth.onAuthenticated(false /* used backup */, null);
            } else {
                // The user canceled or didn’t complete the lock screen
                // operation. Go to error/cancellation flow.
            	fingerprintAuth.onCancelled();
            }
            dismissAllowingStateLoss();
        }
    }

    @Override
    public void onAuthenticated(FingerprintManager.AuthenticationResult result) {
        // Callback from FingerprintUiHelper. Let the activity know that authentication was
        // successful.
    	fingerprintAuth.onAuthenticated(true /* withFingerprint */, result);
        dismissAllowingStateLoss();
    }

    @Override
    public void onError(CharSequence errString) {
        if (!fingerprintAuth.mDisableBackup) {
            if (getActivity() != null && isAdded()) {
                goToBackup();
            }
        } else {
        	fingerprintAuth.onError(errString);
            dismissAllowingStateLoss();

        }
    }

    @Override
    public void onCancel(DialogInterface dialog) {
        super.onCancel(dialog);
        fingerprintAuth.onCancelled();
    }

    /**
     * Enumeration to indicate which authentication method the user is trying to authenticate with.
     */
    public enum Stage {
        FINGERPRINT,
        NEW_FINGERPRINT_ENROLLED,
        BACKUP
    }

	public void setFingerprintAuth(FingerprintAuth fingerprintAuth) {
		this.fingerprintAuth = fingerprintAuth;
	}
}
