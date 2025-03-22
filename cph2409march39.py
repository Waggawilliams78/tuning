#!/usr/bin/env python3
"""
OnePlus Nord CE2 Lite (CPH2409) Limitless Diagnostic & Future‑Proofing Toolkit v3.1
Oxygen OS 14 – Designed for non‑rooted devices

This script gathers comprehensive diagnostics (hardware, network, cellular,
Wi‑Fi, thermal, battery, performance, codec, Bluetooth, telephony, SIM, IMEI,
sensor, memory, storage, CPU governor) and then produces bespoke upgrade
recommendations to push the device into the next decade. Many cellular and
kernel-level parameters (like LTE cell identity or full carrier aggregation)
remain restricted on non‑rooted devices, so the script logs recommendations
for manual or future automated improvements.
"""

import subprocess
import logging
import argparse
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class CPH2409Limitless:
    DEVICE_MODEL = "CPH2409"
    OS_VERSION = "Oxygen OS 14"
    ADB_DEVICE = "5f1b6dec"  # Default ADB device ID

    # Configuration for UK three/smarty carriers
    NETWORK_PROFILE = {
        'nr_mode': 79,
        'dns_primary': '212.183.64.3',
        'dns_secondary': '212.183.67.3',
        'expected_operators': ['three', 'smarty'],
        'ca_bands': '1,3,7,20,28,32,38,41,n78'
    }
    
    THERMAL_ZONES = ['thermal_zone5']

    def __init__(self, verbose=False, non_rooted=True, upgrade=False):
        self.verbose = verbose
        self.non_rooted = non_rooted
        self.upgrade = upgrade
        self.logger = self._configure_logging(verbose)
        self.report_data = {
            'timestamp': datetime.now().isoformat(),
            'metrics': {},
            'upgrade_recommendations': []
        }

    def _configure_logging(self, verbose):
        logger = logging.getLogger('CPH2409_Limitless')
        logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        return logger

    def adb_command(self, cmd, description, retries=3):
        """Execute an ADB command with retries. For non‑rooted devices, fallback messages are logged."""
        full_cmd = f"adb -s {self.ADB_DEVICE} {cmd}"
        for attempt in range(retries):
            try:
                result = subprocess.run(full_cmd, shell=True, check=True,
                                          capture_output=True, text=True, timeout=15)
                output = result.stdout.strip()
                if output:
                    self.logger.info(f"✅ {description}: {output}")
                    self._add_to_report(description, output)
                    return output
                else:
                    msg = "No data (possible non-root limitation)"
                    self.logger.warning(f"⚠️ {description} returned empty output ({msg})")
                    self._add_to_report(description, msg)
                    return ""
            except subprocess.TimeoutExpired:
                self.logger.warning(f"⌛ Timeout on {description} (Attempt {attempt+1}/{retries})")
            except subprocess.CalledProcessError as e:
                error_msg = (e.stderr or str(e))[:100]
                self.logger.warning(f"⚠️ {description} failed: {error_msg}")
                self._add_to_report(description, f"Error: {error_msg}")
            time.sleep(2)
        return ""

    def _add_to_report(self, section, data):
        self.report_data['metrics'][section] = data

    def _add_upgrade_recommendation(self, recommendation):
        self.report_data.setdefault('upgrade_recommendations', []).append(recommendation)
        self.logger.info(f"Upgrade Recommendation: {recommendation}")

    # --- Diagnostics Methods ---
    def configure_network(self):
        self.logger.info("📡 Configuring 5G Network Parameters")
        if self.non_rooted:
            msg = "Not available on non-rooted devices"
            self.logger.info("Skipping network reconfiguration in non-rooted mode")
            self._add_to_report("5G NR Mode Configuration", msg)
        else:
            self.adb_command(f"shell settings put global preferred_network_mode {self.NETWORK_PROFILE['nr_mode']}",
                             "5G NR Mode Configuration")
            current_mode = self.adb_command("shell settings get global preferred_network_mode",
                                            "Current Network Mode Verification")
            if current_mode != str(self.NETWORK_PROFILE['nr_mode']):
                self.logger.warning("❌ 5G Configuration Verification Failed")

    def hardware_diagnostics(self):
        self.logger.info("🔧 Running Hardware Diagnostics")
        self.adb_command("shell getprop ro.hardware", "Hardware Platform")
        self.adb_command("shell getprop ro.product.board", "Product Board")
        self.adb_command("shell getprop ro.build.description", "Build Description")
        # The report shows: Hardware Platform: qcom, Product Board: holi

    def cellular_analysis(self):
        self.logger.info("📶 Running Cellular Diagnostics")
        self.adb_command("shell dumpsys telephony.registry | grep 'mSignalStrength'", "Signal Strength")
        if self.non_rooted:
            msg = "Restricted on non-rooted devices"
            self._add_to_report("LTE Cell Identity", msg)
            self._add_to_report("Data Network Type", msg)
        else:
            self.adb_command("shell dumpsys telephony.registry | grep 'mCellIdentityLte'", "LTE Cell Identity")
            self.adb_command("shell dumpsys telephony.registry | grep 'mDataNetworkType'", "Data Network Type")
        operator = self.adb_command("shell getprop gsm.operator.alpha", "Operator Name")
        normalized = operator.strip().rstrip(',').lower()
        expected = [op.lower() for op in self.NETWORK_PROFILE['expected_operators']]
        if not any(exp in normalized for exp in expected):
            self.logger.warning(f"⚠️ Unexpected operator: expected {expected}, got '{normalized}'")

    def cell_tower_analysis(self):
        self.logger.info("📡 Running Cell Tower Diagnostics")
        self.adb_command("shell dumpsys telephony.registry | grep 'mCellInfo'", "Cell Info")
        self.adb_command("shell dumpsys telephony.registry | grep 'mServiceState'", "Service State")

    def carrier_diagnostics(self):
        self.logger.info("📱 Running Carrier Diagnostics")
        self.adb_command("shell getprop gsm.operator.iso-country", "Operator ISO Country")
        if self.non_rooted:
            msg = "Not available on non-rooted devices"
            self._add_to_report("Carrier Aggregation Status", msg)
        else:
            self.adb_command("shell dumpsys telephony.registry | grep 'mLteCa'", "Carrier Aggregation Status")

    def supported_bands_analysis(self):
        self.logger.info("📡 Running Supported Bands Analysis")
        if self.non_rooted:
            alt = self.adb_command("shell getprop | grep -i band", "Supported Bands (Alternative)")
            if not alt:
                self._add_to_report("Supported Bands", "Not available on non-rooted devices")
        else:
            self.adb_command("shell dumpsys telephony.registry | grep -i 'band'", "Supported Bands Info")

    def wifi_analysis(self):
        self.logger.info("📶 Running Wi‑Fi Diagnostics")
        self.adb_command("shell dumpsys wifi | grep 'Wi-Fi is'", "Wi‑Fi Status")
        self.adb_command("shell dumpsys wifi | grep 'SSID'", "Connected SSID")
        self.adb_command("shell dumpsys wifi | grep 'Channel'", "Wi‑Fi Channel")
        self.adb_command("shell dumpsys wifi | grep 'Frequency'", "Wi‑Fi Frequency")

    def thermal_analysis(self):
        self.logger.info("🌡️ Running Thermal Diagnostics")
        self.adb_command(f"shell cat /sys/class/thermal/{self.THERMAL_ZONES[0]}/temp", "Thermal Zone 5 Temperature")
        if self.non_rooted:
            self._add_to_report("GPU Frequency Check", "Not available on non-rooted devices")
        else:
            self.adb_command("shell cat /sys/class/kgsl/kgsl-3d0/devfreq/cur_freq", "GPU Frequency Check")
        self.adb_command("shell cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "CPU Frequency Check")

    def battery_analysis(self):
        self.logger.info("🔋 Running Battery Diagnostics")
        self.adb_command("shell dumpsys battery | grep level", "Battery Level")
        self.adb_command("shell dumpsys battery | grep temperature", "Battery Temperature")

    def performance_benchmark(self):
        self.logger.info("📊 Running Performance Benchmark")
        self.adb_command("shell ping -c 10 8.8.8.8", "Network Latency Test")

    def codec_analysis(self):
        self.logger.info("🎵 Running Codec Diagnostics")
        if self.non_rooted:
            self._add_to_report("Available Media Codecs", "Not available on non-rooted devices")
        else:
            self.adb_command("shell media codec list", "Available Media Codecs")

    def alternative_media_codec_info(self):
        self.logger.info("🎵 Running Alternative Media Codec Diagnostics")
        alt = self.adb_command("shell getprop ro.config.media_codec", "Alternative Media Codec Info")
        if not alt:
            self._add_to_report("Alternative Media Codec Info", "Not available on non-rooted devices")

    def bluetooth_analysis(self):
        self.logger.info("🔵 Running Bluetooth Diagnostics")
        self.adb_command("shell settings get global bluetooth_on", "Bluetooth Enabled State")
        self.adb_command("shell dumpsys bluetooth_manager | grep 'Adapter'", "Bluetooth Adapter Info")

    def full_telephony_dump(self):
        self.logger.info("📄 Retrieving Full Telephony Dump")
        dump = self.adb_command("shell dumpsys telephony", "Full Telephony Dump")
        if len(dump) > 2000:
            dump = dump[:2000] + "\n...[truncated]"
        self._add_to_report("Full Telephony Dump", dump)

    def alternative_telephony_dump(self):
        self.logger.info("📄 Retrieving Alternative Telephony Dump")
        alt_dump = self.adb_command("shell dumpsys phone", "Alternative Telephony Dump")
        if len(alt_dump) > 2000:
            alt_dump = alt_dump[:2000] + "\n...[truncated]"
        self._add_to_report("Alternative Telephony Dump", alt_dump)

    def sim_diagnostics(self):
        self.logger.info("📱 Running SIM Diagnostics")
        self.adb_command("shell getprop gsm.sim.state", "SIM State")
        self.adb_command("shell getprop gsm.operator.numeric", "Operator Numeric")

    def imei_diagnostics(self):
        self.logger.info("📱 Running IMEI Diagnostics")
        if self.non_rooted:
            self._add_to_report("IMEI Info", "Not accessible on non-rooted devices")
        else:
            self.adb_command("shell service call iphonesubinfo 1", "IMEI Info")

    def sensor_diagnostics(self):
        self.logger.info("📡 Running Sensor Diagnostics")
        self.adb_command("shell dumpsys sensorservice", "Sensor Service Dump")

    def memory_diagnostics(self):
        self.logger.info("💾 Running Memory Diagnostics")
        self.adb_command("shell dumpsys meminfo", "Memory Info")

    def storage_diagnostics(self):
        self.logger.info("💽 Running Storage Diagnostics")
        self.adb_command("shell df", "Storage Usage")

    def cpu_governor_diagnostics(self):
        self.logger.info("🖥️ Running CPU Governor Diagnostics")
        self.adb_command("shell cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "CPU Governor")

    # --- Future‑Proof Upgrade Recommendations ---
    def future_proof_upgrades(self):
        self.logger.info("🚀 Evaluating Future‑Proof Upgrade Recommendations")
        # Cellular: Although full carrier aggregation data isn’t available, recommend firmware updates.
        self._add_upgrade_recommendation("Confirm with your carrier (SMARTY) that your network settings are optimized for LTE and 5G. Consider enrolling in beta OTA updates to unlock full carrier aggregation features when available.")
        # Performance tweaks via system settings (non‑rooted, so recommendations only)
        self._add_upgrade_recommendation("Use ADB to reduce animation scales and disable non-essential background services for a snappier UI.")
        # Wi‑Fi optimization based on frequency data
        wifi_freq = self.adb_command("shell dumpsys wifi | grep 'Frequency'", "Wi‑Fi Frequency")
        
