/**
 * Android Play Store Policy Configuration
 * Maps Google Play Store Developer Program Policies to compliance categories
 */

export const PLAY_STORE_CATEGORIES = {
  SAFETY: {
    name: 'Safety',
    policies: [
      {
        id: 'SP01',
        name: 'Inappropriate Content',
        guideline: 'Content Policies 1.0',
        description: 'Apps must not contain inappropriate or offensive content',
        checks: ['sexual content', 'violence', 'discriminatory content', 'harmful content'],
      },
      {
        id: 'SP02',
        name: 'Child Safety',
        guideline: 'Families Policy',
        description: 'Apps designed for children must comply with Play Families policies',
        checks: ['kids category', 'age-appropriate', 'parental controls', 'COPPA'],
      },
      {
        id: 'SP03',
        name: 'User-Generated Content Moderation',
        guideline: 'User-Generated Content Policy',
        description: 'Apps with UGC must have content moderation systems',
        checks: ['content filtering', 'reporting mechanisms', 'blocking users'],
      },
    ],
  },
  MONETIZATION: {
    name: 'Monetization & Payments',
    policies: [
      {
        id: 'MP01',
        name: 'In-App Purchases',
        guideline: 'Payments Policy',
        description: 'Apps selling digital goods must use Google Play billing',
        checks: ['Google Play billing', 'real currency', 'digital goods', 'subscriptions'],
      },
      {
        id: 'MP02',
        name: 'Subscription Management',
        guideline: 'Subscriptions Policy',
        description: 'Subscriptions must be easy to cancel and manage',
        checks: ['cancel subscription', 'restore purchases', 'free trial'],
      },
      {
        id: 'MP03',
        name: 'Advertising Policies',
        guideline: 'Ads Policy',
        description: 'Ads must be clearly identifiable and not deceptive',
        checks: ['ad labeling', 'interstitial ads', 'rewarded ads', 'ad frequency'],
      },
      {
        id: 'MP04',
        name: 'Misleading Claims',
        guideline: 'Deceptive Behavior Policy',
        description: 'Apps must not make misleading claims about functionality',
        checks: ['fake functionality', 'misleading descriptions', 'impersonation'],
      },
    ],
  },
  PRIVACY: {
    name: 'Privacy, Security & Deception',
    policies: [
      {
        id: 'PR01',
        name: 'Data Collection Disclosure',
        guideline: 'Data Safety Section',
        description: 'Apps must accurately disclose data collection in Data Safety form',
        checks: ['data collection', 'personal data', 'data sharing', 'data deletion'],
      },
      {
        id: 'PR02',
        name: 'Sensitive Permissions',
        guideline: 'Permissions Policy',
        description: 'Apps must request permissions that are necessary and clearly justified',
        checks: [
          'READ_CONTACTS', 'READ_SMS', 'CALL_LOG', 'CAMERA', 'RECORD_AUDIO',
          'ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'READ_CALENDAR',
        ],
      },
      {
        id: 'PR03',
        name: 'Background Location',
        guideline: 'Background Location Policy',
        description: 'Background location access requires clear user benefit',
        checks: ['ACCESS_BACKGROUND_LOCATION', 'location tracking', 'continuous location'],
      },
      {
        id: 'PR04',
        name: 'App Security',
        guideline: 'Security Best Practices',
        description: 'Apps must use secure coding practices and up-to-date dependencies',
        checks: ['cleartext traffic', 'certificate pinning', 'obfuscation', 'deprecated APIs'],
      },
      {
        id: 'PR05',
        name: 'Malware & Harmful Behavior',
        guideline: 'Malware Policy',
        description: 'Apps must not contain malware or harmful functionality',
        checks: ['telephony', 'SMS interception', 'rooting', 'device exploits'],
      },
    ],
  },
  FUNCTIONALITY: {
    name: 'Functionality & Performance',
    policies: [
      {
        id: 'FP01',
        name: 'Core Functionality',
        guideline: 'Core Functionality Policy',
        description: 'Apps must have substantial, appropriate functionality',
        checks: ['minimum functionality', 'template apps', 'web apps wrapped'],
      },
      {
        id: 'FP02',
        name: 'Stability',
        guideline: 'Stability Policy',
        description: 'Apps must not crash or cause device instability',
        checks: ['crash reports', 'ANR', 'force close', 'compatibility'],
      },
      {
        id: 'FP03',
        name: 'Performance',
        guideline: 'Performance Policy',
        description: 'Apps must not excessively drain battery or resources',
        checks: ['background execution', 'excessive wakelocks', 'memory leaks'],
      },
      {
        id: 'FP04',
        name: 'Play Store Listing',
        guideline: 'Listing Content Policy',
        description: 'App listing must be accurate and complete',
        checks: ['app icon', 'screenshots', 'description accuracy', 'release notes'],
      },
    ],
  },
  TECHNICAL: {
    name: 'Technical Requirements',
    policies: [
      {
        id: 'TP01',
        name: 'Target SDK Version',
        guideline: 'Target API Level Requirement',
        description: 'Apps must target recent Android API levels',
        checks: ['targetSdkVersion', 'compileSdkVersion', 'minSdkVersion'],
      },
      {
        id: 'TP02',
        name: 'App Bundle & APK',
        guideline: 'Android App Bundle Policy',
        description: 'APKs must be properly signed and optimized',
        checks: ['v1 signature', 'v2 signature', 'v3 signature', 'alignment', 'compression'],
      },
      {
        id: 'TP03',
        name: 'Instant Apps',
        guideline: 'Instant Apps Policy',
        description: 'Instant app modules must meet size limits',
        checks: ['instant feature module', 'base module size'],
      },
      {
        id: 'TP04',
        name: 'App Clips',
        guideline: 'App Clips Policy',
        description: 'App Clips must be lightweight and focused',
        checks: ['App Clip size limit', 'relevant functionality'],
      },
    ],
  },
};

/**
 * Maps Play Store policy violations to severity levels
 */
export const SEVERITY_MAP = {
  CRITICAL: [
    'malware', 'harmful behavior', 'telephony', 'SMS interception',
    'rooting', 'device exploits', 'data theft', 'impersonation',
  ],
  HIGH: [
    'in-app purchases without Google Play billing', 'misleading claims',
    'background location without justification', 'COPPA violation',
    'deceptive behavior', 'unauthorized data collection',
  ],
  MEDIUM: [
    'permission overuse', 'inadequate content moderation',
    'ad policy violation', 'subscription management issues',
    'crash-prone', 'template app',
  ],
  LOW: [
    'listing optimization', 'metadata issues', 'minor policy deviation',
    'best practice improvement',
  ],
};

/**
 * Maps file extensions to Play Store policy relevance
 */
export const RELEVANT_EXTENSIONS = new Set([
  '.java', '.kt', '.kts', // Kotlin/Java source
  '.xml', // Android resources and manifest
  '.gradle', '.gradle.kts', // Build files
  '.properties', // Config files
  '.json', // Firebase, manifest merger
  '.txt', '.md', // Documentation
  '.proto', // Protocol buffers
  '.yaml', '.yml', // YAML configs
  '.xml', # XML resources
]);

/**
 * Directories to skip during analysis
 */
export const SKIP_DIRS = new Set([
  'node_modules', '.git', '.gradle', 'build', 'app/build',
  '.idea', '.app', '*.apk', '*.aab', 'META-INF',
  'lib', 'libs', 'bin', 'obj', 'generated',
  '__pycache__', 'vendor', '.dart_tool',
  'res/drawable-*', 'res/values-*', # Skip locale-specific resources
]);

/**
 * Max file size per source file (bytes)
 */
export const MAX_FILE_SIZE = 50_000;

/**
 * Max total content size for context (bytes)
 */
export const MAX_TOTAL_CONTENT = 350_000;

/**
 * Severity threshold labels
 */
export const SEVERITY_LABELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

/**
 * Get severity for a finding based on keywords
 */
export function getSeverityForFinding(findingText) {
  const text = findingText.toLowerCase();
  for (const severity of SEVERITY_LABELS) {
    const keywords = SEVERITY_MAP[severity];
    for (const keyword of keywords) {
      if (text.includes(keyword.toLowerCase())) {
        return severity;
      }
    }
  }
  return 'MEDIUM'; // Default severity
}
