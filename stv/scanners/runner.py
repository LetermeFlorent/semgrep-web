"""Helpers partages par les scanners externes : exec de process, mapping severite."""
import subprocess


def run_command(cmd, timeout=1800):
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = process.communicate(timeout=timeout)
    return process.returncode, out, err


def severity_of(raw):
    # normalise les severites des outils vers ERROR / WARNING / INFO
    level = (raw or "").upper()
    if level in ("CRITICAL", "HIGH"):
        return "ERROR"
    if level in ("MEDIUM", "MODERATE"):
        return "WARNING"
    return "INFO"
