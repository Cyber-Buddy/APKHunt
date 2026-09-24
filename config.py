# Configuration file for Apkhunt
import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent

# Tool paths
JADX_PATH = os.getenv('JADX_PATH', 'jadx')
APKTOOL_PATH = os.getenv('APKTOOL_PATH', 'apktool')

# JADX performance optimization flags
JADX_THREADS = int(os.getenv('JADX_THREADS', '8'))  # Increase from default 4 to 8
JADX_DECOMPILATION_MODE = os.getenv('JADX_DECOMPILATION_MODE', 'auto')
JADX_NO_DEBUG_INFO = os.getenv('JADX_NO_DEBUG_INFO', 'true').lower() == 'true'
JADX_AUTO_TIMEOUT = int(os.getenv('JADX_AUTO_TIMEOUT', '600'))
JADX_SIMPLE_TIMEOUT = int(os.getenv('JADX_SIMPLE_TIMEOUT', '600'))
JADX_STALL_TIMEOUT = int(os.getenv('JADX_STALL_TIMEOUT', '180'))
JADX_SIMPLE_RETRY = os.getenv('JADX_SIMPLE_RETRY', 'true').lower() == 'true'
JADX_PER_DEX_RETRY = os.getenv('JADX_PER_DEX_RETRY', 'true').lower() == 'true'
JADX_SHOW_BAD_CODE = os.getenv('JADX_SHOW_BAD_CODE', 'false').lower() == 'true'
JADX_DEX_TIMEOUT = int(os.getenv('JADX_DEX_TIMEOUT', '120'))
JADX_PER_DEX_BUDGET = int(os.getenv('JADX_PER_DEX_BUDGET', '600'))
TRUFFLEHOG_TIMEOUT = int(os.getenv('TRUFFLEHOG_TIMEOUT', '240'))

# Secrets detection configuration
ENHANCED_SECRETS_VALIDATION = os.getenv('ENHANCED_SECRETS_VALIDATION', 'true').lower() == 'true'
SECRETS_ENTROPY_THRESHOLD = float(os.getenv('SECRETS_ENTROPY_THRESHOLD', '5.0'))  # Increased for aggressive filtering

# Aggressive false positive reduction
AGGRESSIVE_FALSE_POSITIVE_FILTERING = os.getenv('AGGRESSIVE_FALSE_POSITIVE_FILTERING', 'true').lower() == 'true'
SKIP_RESOURCE_FILES = os.getenv('SKIP_RESOURCE_FILES', 'true').lower() == 'true'  # Skip XML/properties files
MIN_SECRET_LENGTH = int(os.getenv('MIN_SECRET_LENGTH', '16'))  # Minimum length for secrets

# Fine-tuned entropy thresholds for different secret types
AWS_SECRET_ENTROPY_THRESHOLD = float(os.getenv('AWS_SECRET_ENTROPY_THRESHOLD', '4.8'))  # AWS secrets
GENERAL_SECRET_ENTROPY_THRESHOLD = float(os.getenv('GENERAL_SECRET_ENTROPY_THRESHOLD', '4.5'))  # General secrets

# Decompiler strategy configuration
USE_APKTOOL_FALLBACK = os.getenv('USE_APKTOOL_FALLBACK', 'true').lower() == 'true'  # Use Apktool only when JADX fails

# New strategy: JADX primary, Apktool only as fallback
JADX_PRIMARY_APKTOOL_FALLBACK = os.getenv('JADX_PRIMARY_APKTOOL_FALLBACK', 'true').lower() == 'true'

# Apktool scanning configuration
APKTOOL_ESSENTIAL_FILES = os.getenv('APKTOOL_ESSENTIAL_FILES', 'AndroidManifest.xml,res/values/strings.xml,res/values/colors.xml,res/values/styles.xml').split(',')

# Folder paths
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DECOMPILED_FOLDER = os.path.join(BASE_DIR, 'decompiled_apks')
GENERATED_REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

# File paths
STATE_FOLDER = os.getenv('APKHUNT_STATE_DIR', str(BASE_DIR))
SCAN_HISTORY_FILE = os.path.join(STATE_FOLDER, 'scan_history.json')
SCAN_JOBS_FILE = os.path.join(STATE_FOLDER, 'scan_jobs.json')
RULES_FILE = os.path.join(BASE_DIR, 'rules.json')

# Flask configuration
SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG_MODE = os.getenv('DEBUG_MODE', 'false').lower() == 'true'
DECOMPILER_TIMEOUT = int(os.getenv('DECOMPILER_TIMEOUT', '1200'))  # Large APKs may need longer than 10 minutes.

# Hostile APKs are archives. These bounds are checked before any decompiler is invoked.
MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', str(200 * 1024 * 1024)))
MAX_APK_ARCHIVE_MEMBERS = int(os.getenv('MAX_APK_ARCHIVE_MEMBERS', '100000'))
MAX_APK_UNCOMPRESSED_SIZE = int(os.getenv('MAX_APK_UNCOMPRESSED_SIZE', str(2 * 1024 * 1024 * 1024)))
MAX_APK_COMPRESSION_RATIO = int(os.getenv('MAX_APK_COMPRESSION_RATIO', '100'))

def create_dirs():
    """Create necessary directories if they don't exist"""
    for directory in [UPLOAD_FOLDER, DECOMPILED_FOLDER, GENERATED_REPORTS_DIR, STATE_FOLDER]:
        os.makedirs(directory, exist_ok=True)
