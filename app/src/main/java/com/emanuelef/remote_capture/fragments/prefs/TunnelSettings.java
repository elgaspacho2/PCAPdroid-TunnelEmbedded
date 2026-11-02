/*
 * This file is part of PCAPdroid.
 *
 * PCAPdroid is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * PCAPdroid is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PCAPdroid.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2026 - PCAPdroid TunnelEmbedded
 */

package com.emanuelef.remote_capture.fragments.prefs;

import android.os.Bundle;
import android.text.InputType;
import android.text.TextUtils;

import androidx.annotation.Nullable;
import androidx.preference.DropDownPreference;
import androidx.preference.EditTextPreference;
import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;
import androidx.preference.PreferenceManager;
import androidx.preference.SwitchPreference;

import com.emanuelef.remote_capture.Log;
import com.emanuelef.remote_capture.R;
import com.emanuelef.remote_capture.Utils;
import com.emanuelef.remote_capture.model.Prefs;
import com.emanuelef.remote_capture.model.WgConfig;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Settings for the tunnel embedded in the app (see docs/tunnel_embedded.md).
 *
 * Two things this screen deliberately does:
 *
 *  - it never shows the raw configuration as a preference summary, since that text holds
 *    the WireGuard private key and the settings list is the first thing a screenshot
 *    catches. A parsed, key-free recap is shown instead;
 *  - it rejects an invalid configuration at the point it is typed, with the parser's own
 *    message, rather than letting the capture fail later with no clue as to why.
 */
public class TunnelSettings extends SettingsSubFragment {
    private static final String TAG = "TunnelSettings";

    private SwitchPreference mEnabled;
    private EditTextPreference mConfig;
    private DropDownPreference mDatapath;
    private Preference mDatapathInfo;
    private Preference mWarning;
    private PreferenceCategory mPeerCategory;
    private PreferenceCategory mDatapathCategory;

    @Override
    public void onCreatePreferences(@Nullable Bundle savedInstanceState, @Nullable String rootKey) {
        setPreferencesFromResource(R.xml.tunnel_preferences, rootKey);

        mEnabled = Objects.requireNonNull(findPreference(Prefs.PREF_TUNNEL_ENABLED));
        mConfig = Objects.requireNonNull(findPreference(Prefs.PREF_TUNNEL_CONFIG));
        mDatapath = Objects.requireNonNull(findPreference(Prefs.PREF_TUNNEL_DATAPATH));
        mDatapathInfo = Objects.requireNonNull(findPreference("tunnel_datapath_info"));
        mWarning = Objects.requireNonNull(findPreference("tunnel_warning"));
        mPeerCategory = Objects.requireNonNull(findPreference("tunnel_peer"));
        mDatapathCategory = Objects.requireNonNull(findPreference("tunnel_datapath_category"));

        /* A wg-quick file is multi-line, so the single-line default would make it
         * impossible to paste and impossible to read back. */
        mConfig.setOnBindEditTextListener(editText -> {
            editText.setInputType(InputType.TYPE_CLASS_TEXT
                    | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                    | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
            editText.setSingleLine(false);
            editText.setMinLines(8);
            editText.setMaxLines(20);
            editText.setHorizontallyScrolling(true);
        });

        mConfig.setOnPreferenceChangeListener((preference, newValue) -> {
            String text = (newValue != null) ? newValue.toString() : "";

            if (text.trim().isEmpty()) {
                // Clearing the configuration is how the user removes it
                updateConfigSummary("");
                refresh(mEnabled.isChecked());
                return true;
            }

            try {
                WgConfig.parse(text);
            } catch (WgConfig.ParseException e) {
                Log.w(TAG, "Rejected tunnel configuration: " + e.getMessage());
                Utils.showToastLong(requireContext(), R.string.tunnel_invalid_config, e.getMessage());
                return false;
            }

            updateConfigSummary(text);
            /* The new value is only committed to SharedPreferences after this listener
             * returns true, and buildWarning reads it from there, so the refresh has to
             * wait for the next loop iteration. */
            requireView().post(() -> refresh(mEnabled.isChecked()));
            return true;
        });

        mEnabled.setOnPreferenceChangeListener((preference, newValue) -> {
            refresh((boolean) newValue);
            return true;
        });

        mDatapath.setOnPreferenceChangeListener((preference, newValue) -> {
            updateDatapathInfo(Prefs.getTunnelDatapath(newValue.toString()));
            // See the comment above on why this is posted
            requireView().post(() -> refresh(mEnabled.isChecked()));
            return true;
        });

        updateConfigSummary(Prefs.getTunnelConfig(getPrefs()));
        updateDatapathInfo(Prefs.getTunnelDatapath(getPrefs()));
        refresh(mEnabled.isChecked());
    }

    private android.content.SharedPreferences getPrefs() {
        return PreferenceManager.getDefaultSharedPreferences(requireContext());
    }

    /* Shows what the configuration actually contains, without ever printing a key */
    private void updateConfigSummary(String text) {
        if (text.trim().isEmpty()) {
            mConfig.setSummary(R.string.tunnel_config_not_set);
            return;
        }

        try {
            WgConfig cfg = WgConfig.parse(text);
            StringBuilder addresses = new StringBuilder();

            for (WgConfig.InetPrefix addr: cfg.addresses) {
                if (addresses.length() > 0)
                    addresses.append(", ");
                addresses.append(addr.toString());
            }

            mConfig.setSummary(getString(R.string.tunnel_config_recap,
                    cfg.endpointHost + ":" + cfg.endpointPort,
                    addresses.toString(),
                    cfg.mtu));
        } catch (WgConfig.ParseException e) {
            /* Reachable when a configuration stored by an older build, or restored from a
             * backup, no longer parses. Say so instead of showing a stale recap. */
            mConfig.setSummary(getString(R.string.tunnel_invalid_config, e.getMessage()));
        }
    }

    private void updateDatapathInfo(Prefs.TunnelDatapath datapath) {
        mDatapathInfo.setSummary((datapath == Prefs.TunnelDatapath.L4)
                ? R.string.tunnel_datapath_l4_info
                : R.string.tunnel_datapath_l3_info);
    }

    private void refresh(boolean enabled) {
        mPeerCategory.setVisible(enabled);
        mDatapathCategory.setVisible(enabled);

        if (!enabled) {
            mWarning.setVisible(false);
            return;
        }

        String warning = buildWarning();
        mWarning.setVisible(warning != null);
        if (warning != null)
            mWarning.setSummary(warning);
    }

    /* Returns the reason the tunnel would not work with the current settings, or null.
     *
     * The capture service performs the same checks and refuses to start; surfacing them
     * here means the user finds out while configuring, not when the capture dies. */
    @Nullable
    private String buildWarning() {
        android.content.SharedPreferences prefs = getPrefs();

        if (Prefs.getTunnelConfig(prefs).trim().isEmpty())
            return getString(R.string.tunnel_no_config_warning);

        if (Prefs.isRootCaptureEnabled(prefs))
            return getString(R.string.tunnel_root_warning);

        if (Prefs.getTunnelDatapath(prefs) == Prefs.TunnelDatapath.L4)
            return getString(R.string.tunnel_l4_unavailable);

        List<String> incompatible = new ArrayList<>();
        if (Prefs.getTlsDecryptionEnabled(prefs))
            incompatible.add(getString(R.string.tls_decryption));
        if (Prefs.getSocks5Enabled(prefs))
            incompatible.add(getString(R.string.socks5_proxy));
        if (Prefs.isPortMappingEnabled(prefs))
            incompatible.add(getString(R.string.port_mapping));

        if (!incompatible.isEmpty())
            return getString(R.string.tunnel_incompatible_l3, TextUtils.join(", ", incompatible));

        return null;
    }
}
