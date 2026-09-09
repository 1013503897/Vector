/*
 * <!--This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2021 LSPosed Contributors-->
 */

package org.lsposed.manager.ui.fragment;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.EditTextPreference;
import androidx.preference.ListPreference;
import androidx.preference.Preference;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.TwoStatePreference;

import org.lsposed.manager.ConfigManager;
import org.lsposed.manager.R;
import org.lsposed.manager.databinding.FragmentUnpackBinding;

/**
 * Manager front-end for the stealth unpacker. Collects a target package + preset + overrides
 * and calls the daemon (ConfigManager.armUnpack -> UnpackConfig -> resetprop). This is the UI
 * twin of tools/vunpack; the native unpacker is untouched -- it just reads the props we set.
 */
public class UnpackFragment extends BaseFragment {
    FragmentUnpackBinding binding;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        binding = FragmentUnpackBinding.inflate(inflater, container, false);
        binding.appBar.setLiftable(true);
        setupToolbar(binding.toolbar, binding.clickView, R.string.unpack_title);
        if (savedInstanceState == null) {
            getChildFragmentManager().beginTransaction().add(R.id.unpack_container, new UnpackPreferenceFragment()).commitNow();
        }
        return binding.getRoot();
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
    }

    public static class UnpackPreferenceFragment extends PreferenceFragmentCompat {
        private UnpackFragment parentFragment;

        @Override
        public void onAttach(@NonNull Context context) {
            super.onAttach(context);
            parentFragment = (UnpackFragment) requireParentFragment();
        }

        @Override
        public void onDetach() {
            super.onDetach();
            parentFragment = null;
        }

        @Override
        public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
            addPreferencesFromResource(R.xml.unpack_prefs);
            boolean installed = ConfigManager.isBinderAlive();

            Preference arm = findPreference("unpack_arm");
            if (arm != null) {
                arm.setEnabled(installed);
                arm.setOnPreferenceClickListener(p -> {
                    doArm();
                    return true;
                });
            }

            Preference disarm = findPreference("unpack_disarm");
            if (disarm != null) {
                disarm.setEnabled(installed);
                disarm.setOnPreferenceClickListener(p -> {
                    doDisarm();
                    return true;
                });
            }

            Preference status = findPreference("unpack_status");
            if (status != null) {
                status.setOnPreferenceClickListener(p -> {
                    refreshStatus();
                    return true;
                });
            }

            if (installed) refreshStatus();
        }

        // ---- helpers ----

        private boolean switchOn(String key) {
            Preference p = findPreference(key);
            return p instanceof TwoStatePreference && ((TwoStatePreference) p).isChecked();
        }

        private String editText(String key) {
            Preference p = findPreference(key);
            if (p instanceof EditTextPreference) {
                String t = ((EditTextPreference) p).getText();
                return t == null ? "" : t.trim();
            }
            return "";
        }

        private String listValue(String key, String dflt) {
            Preference p = findPreference(key);
            if (p instanceof ListPreference) {
                String v = ((ListPreference) p).getValue();
                if (v != null) return v;
            }
            return dflt;
        }

        private void setStatusSummary(CharSequence text) {
            Preference status = findPreference("unpack_status");
            if (status != null && text != null) status.setSummary(text);
        }

        private void doArm() {
            if (parentFragment == null) return;
            String pkg = editText("unpack_target");
            if (pkg.isEmpty()) {
                parentFragment.showHint(R.string.unpack_need_target, true);
                return;
            }
            String preset = listValue("unpack_preset", "whole");

            Bundle opts = new Bundle();
            opts.putBoolean("rasp", switchOn("unpack_rasp"));
            opts.putBoolean("dobby", switchOn("unpack_dobby"));
            String extout = listValue("unpack_extout", "default");
            if ("on".equals(extout)) opts.putString("extout", "1");
            else if ("off".equals(extout)) opts.putString("extout", "0");
            String interpMs = editText("unpack_interp_ms");
            if (!interpMs.isEmpty()) opts.putString("interp_ms", interpMs);
            String workerDelay = editText("unpack_worker_delay");
            if (!workerDelay.isEmpty()) opts.putString("worker_delay_ms", workerDelay);

            parentFragment.runAsync(() -> {
                Bundle res = ConfigManager.armUnpack(preset, pkg, opts);
                boolean ok = res.getBoolean("ok", false);
                String summary = ok ? res.getString("summary") : res.getString("error");
                if (parentFragment == null) return;
                parentFragment.runOnUiThread(() -> {
                    if (summary != null) setStatusSummary(summary);
                    parentFragment.showHint(ok ? R.string.unpack_armed : R.string.unpack_failed, ok);
                });
            });
        }

        private void doDisarm() {
            if (parentFragment == null) return;
            parentFragment.runAsync(() -> {
                ConfigManager.disarmUnpack();
                if (parentFragment == null) return;
                parentFragment.runOnUiThread(() -> {
                    refreshStatus();
                    parentFragment.showHint(R.string.unpack_disarmed, true);
                });
            });
        }

        private void refreshStatus() {
            if (parentFragment == null) return;
            parentFragment.runAsync(() -> {
                String st = ConfigManager.getUnpackStatus();
                if (parentFragment == null) return;
                parentFragment.runOnUiThread(() -> setStatusSummary(
                        st == null || st.isEmpty() ? getString(R.string.unpack_status_empty) : st));
            });
        }
    }
}
