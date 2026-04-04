# Android Play Store Compliance Auditor

AI-powered Android app compliance auditor for Google Play Store policies. Upload your `.apk` file and get a comprehensive audit against Google's Developer Program Policies — before you submit.

## Features

- **APK/AAB Analysis** — Upload `.apk` or `.aab` files for automated compliance auditing
- **Full Policy Coverage** — Checks all major Play Store policy categories:
  - Safety (Content & User Safety)
  - Monetization & Payments
  - Privacy & Security
  - Functionality & Performance
  - Technical Requirements
- **Multi-Provider AI** — Bring your own key from Anthropic (Claude), OpenAI (GPT), Google Gemini, or OpenRouter
- **Real-Time Streaming** — Watch your audit report generate live
- **Export Reports** — Download as Markdown or PDF
- **Zero-Trust Security** — Files processed in ephemeral temp storage and deleted immediately

## Architecture

```
android/
├── auditor.js          # Main audit logic - APK extraction, file collection, AI streaming
├── config.js           # Play Store policy mappings, severity levels, relevant file types
├── report-generator.js # Markdown report generation, severity scoring, remediation planning
└── README.md          # This file
```

## Play Store Policy Categories

### 1. Safety (Content & User Safety)
- Inappropriate content filters
- User-generated content moderation
- Child safety / COPPA compliance
- Harmful functionality protections

### 2. Monetization & Payments
- Google Play billing compliance
- Subscription management (cancel, restore)
- Advertising policy compliance
- No misleading claims

### 3. Privacy & Security
- Privacy policy URL requirement
- Data Safety form accuracy
- Sensitive permissions justification
- Background location access
- Secure network traffic (HTTPS)
- Malware patterns detection

### 4. Functionality & Performance
- Substantial app functionality
- Stability and error handling
- Battery and performance
- Complete listing metadata

### 5. Technical Requirements
- Target SDK version currency
- APK signing verification
- No deprecated APIs
- ProGuard/R8 obfuscation

## Usage

### Integration with Next.js API Route

```typescript
// src/app/api/android-audit/route.ts
import { handleAndroidAudit, buildAIRequest, parseAIStreamChunk } from '@/android/auditor';

export const runtime = 'nodejs';
export const maxDuration = 300;

export async function POST(req) {
  // Handle upload and prepare audit data
  const result = await handleAndroidAudit(req);
  
  if (result.error) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }
  
  const { files, apkInfo, systemPrompt, userPrompt, apiKey, provider, model } = result;
  
  // Build AI request
  const { apiUrl, headers, payload } = buildAIRequest(provider, apiKey, model, systemPrompt, userPrompt);
  
  // Stream response back to client...
}
```

### Running Standalone

```javascript
import { handleAndroidAudit } from './auditor.js';

// Process an APK and get audit data
const result = await handleAndroidAudit(uploadRequest);
const { files, apkInfo, systemPrompt, userPrompt } = result;
```

## Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| CRITICAL | Will result in app suspension/rejection | Fix immediately |
| HIGH | Frequently causes policy violations | Fix before submission |
| MEDIUM | May cause rejection depending on reviewer | Review and address |
| LOW | Best practice improvements | Consider fixing |

## Readiness Score

Calculated based on issue severity:
- Each CRITICAL issue: -25 points
- Each HIGH issue: -15 points
- Each MEDIUM issue: -5 points
- Each LOW issue: -1 point

Score 100 = Fully compliant

## Report Structure

1. **Header** — App name, package, version, audit date
2. **Dashboard** — Risk level, readiness score, issue counts
3. **Executive Summary** — 2-3 sentence overview
4. **Policy Compliance Checks** — Detailed findings by category
5. **Remediation Plan** — Prioritized fix list with effort estimates
6. **Submission Readiness** — Final verdict and next steps

## File Types Analyzed

- `.java`, `.kt`, `.kts` — Source code
- `.xml` — AndroidManifest, resources, layouts
- `.gradle`, `.gradle.kts` — Build configuration
- `.properties` — App configuration
- `.json` — Firebase, manifest merger configs
- `.yaml`, `.yml` — CI/CD, tooling configs

## Security Considerations

- **No cloud storage** — Files processed in ephemeral `/tmp` directories
- **BYOK** — API keys stay in browser, never on servers
- **No shell injection** — File extraction uses `execFile` without shell
- **Binary detection** — Binary files are skipped automatically
- **Rate limiting** — 5 requests per IP per minute

## Contributing

Contributions welcome! Please ensure:
- All new policy checks have corresponding guidelines
- Severity mappings are accurate
- Report format maintains consistency

## License

Open source. See repository for details.

---

Built by [Gracias AI](https://gracias.sh) | business@gracias.sh
