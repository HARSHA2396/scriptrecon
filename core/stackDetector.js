const store = require("./store");
const { log } = require("../utils/logger");

/**
 * Enhanced technology stack detection with high accuracy
 * Uses precise fingerprinting, version detection, and confidence scoring
 */

// Comprehensive tech fingerprint database
const TECH_FINGERPRINTS = {
    // Frontend Frameworks - with precise patterns
    "React": {
        patterns: [
            /React\.createElement|ReactDOM\.render|React\.Fragment|\$\._createClass|\$\.react/,
            /__REACT_DEVTOOLS_GLOBAL_HOOK__|__reactInternalInstance|_reactRoot/,
            /window\.__REACT_DEVTOOLS|ReactDOMTestUtils/,
            /import React from ['"]react['"]/,
        ],
        antipatterns: [],
        confidence: 0.95
    },
    "Vue.js": {
        patterns: [
            /__vue__|Vue\.prototype|Vue\.component|Vue\.use/,
            /\._vnode|\._rootVnode|__VUE_DEVTOOLS/,
            /import Vue from ['"]vue['"]/,
            /{{.*?}}.*?v-if|v-bind:|@click/,
        ],
        antipatterns: [],
        confidence: 0.95
    },
    "Angular": {
        patterns: [
            /angular\.(module|controller|service|directive|filter|factory)/,
            /ng-app|ng-model|ng-click|ng-repeat/,
            /@angular\/core|@Component|@NgModule/,
            /function.*\$scope\)\s*\{/,
        ],
        antipatterns: [],
        confidence: 0.95
    },
    "Ember.js": {
        patterns: [
            /Ember\.\w+|__EMBER_VERSION__|__ember_exports__/,
            /App\s*=\s*Ember\.Application\.create/,
            /import.*from ['"]ember["']/,
        ],
        antipatterns: [],
        confidence: 0.92
    },
    "Svelte": {
        patterns: [
            /svelte\/internal|import.*\.svelte/,
            /\$:|$$:|reactive\(/,
        ],
        antipatterns: [],
        confidence: 0.90
    },
    
    // Meta Frameworks
    "Next.js": {
        patterns: [
            /__NEXT_DATA__|__NEXT_ROUTER__|__NEXT_VERSION__|next\/link|next\/image/,
            /^export.*getServerSideProps|getStaticProps/m,
            /import.*from ['"]next['"]/,
        ],
        antipatterns: [],
        confidence: 0.98
    },
    "Nuxt.js": {
        patterns: [
            /__NUXT__|__nuxt_scripts__|nuxt\.version/,
            /export.*async nuxtServerInit/,
            /import.*from ['"]nuxt['"]/,
        ],
        antipatterns: [],
        confidence: 0.98
    },
    "Gatsby": {
        patterns: [
            /___GATSBY_|__GATSBY_ASSET|___loader|___ASSET_PREFIX__|window\.gatsby/,
            /export.*query\s+StaticQuery|useStaticQuery/,
        ],
        antipatterns: [],
        confidence: 0.96
    },
    "SvelteKit": {
        patterns: [
            /sveltekit|import.*from ['"]proper_sveltekit|@sveltejs\/kit/,
        ],
        antipatterns: [],
        confidence: 0.90
    },
    "Remix": {
        patterns: [
            /from ['"]@remix-run|useLoaderData|useFetcher|import.*from ['"]remix['"]/,
        ],
        antipatterns: [],
        confidence: 0.92
    },
    
    // CMS & Backend Frameworks
    "WordPress": {
        patterns: [
            /wp-content|wp-includes|wp-json|wp-admin|wpadminbar/,
            /wp_(?:enqueue_script|localize_script|register_script)/,
        ],
        antipatterns: [],
        confidence: 0.99
    },
    "Shopify": {
        patterns: [
            /Shopify\.|__SHOPIFY_|theme\s*=.*Shopify|window\.Shopify/,
            /cdn\.shopify\.com|shopifycdn\.com|myshopify\.com/,
        ],
        antipatterns: [],
        confidence: 0.98
    },
    "Drupal": {
        patterns: [
            /Drupal\.|drupalSettings|drupal\.theme|drupal\.behaviors/,
            /modules\/system\/js|sites\/all\/modules/,
        ],
        antipatterns: [],
        confidence: 0.95
    },
    "Joomla": {
        patterns: [
            /Joomla\.|com_(?:content|user|login)|joomla\.version/,
            /component\/com_|images\/banners/,
        ],
        antipatterns: [],
        confidence: 0.92
    },
    "Magento": {
        patterns: [
            /Magento\.|MINI_CART|MAGENTO_VERSION|magento/,
            /skin\/(?:frontend|adminhtml)|media\/mage|mage\/|magento\.js/,
        ],
        antipatterns: [],
        confidence: 0.95
    },
    
    // UI/CSS Libraries
    "Bootstrap": {
        patterns: [
            /version.*bootstrap|bootstrap\.(?:css|js)|bootstrap\/dist/,
            /\$\("\.(?:modal|dropdown|alert|tooltip)/,
            /\.modal\(|\.dropdown\(|\.alert\(/,
        ],
        antipatterns: ["tailwind"],
        confidence: 0.92
    },
    "Tailwind CSS": {
        patterns: [
            /tailwindcss|@tailwind base;|tx-\w+|class="[^"]*(?:px-|py-|mt-|mb-)/,
            /tailwind\.config\.js/,
        ],
        antipatterns: [],
        confidence: 0.90
    },
    "Material-UI": {
        patterns: [
            /@material-ui|MuiSvgIcon|material-ui\.com|makeStyles|MuiButton/,
        ],
        antipatterns: [],
        confidence: 0.92
    },
    "Ant Design": {
        patterns: [
            /antd|ant-design|@ant-design|AntTreeSelect|AntTable/,
        ],
        antipatterns: [],
        confidence: 0.90
    },
    
    // Build & Module Tools
    "Webpack": {
        patterns: [
            /webpack(?:_require)?|__webpack_modules__|__webpack_nonce__|__webpack_hash__/,
            /webpackChunk|webpackJsonp|__webpack_exports__|__webpack_public_path__/,
        ],
        antipatterns: [],
        confidence: 0.98
    },
    "Vite": {
        patterns: [
            /import\.meta\.(?:hot|env|url)|__VITE_|\@vite|vite:(?:css|js)/,
        ],
        antipatterns: [],
        confidence: 0.96
    },
    "Parcel": {
        patterns: [
            /parcelRequire|PARCEL_VERSION|parcelModule|import\.meta\.url/,
        ],
        antipatterns: [],
        confidence: 0.94
    },
    "Rollup": {
        patterns: [
            /define\s*\(\s*['"]\w+['"],\s*\[|__esModule|Object\.defineProperty/,
        ],
        antipatterns: [],
        confidence: 0.85
    },
    
    // State Management
    "Redux": {
        patterns: [
            /redux(?:Devtools)?|__REDUX_|store\.dispatch|store\.subscribe|reducer\(state,\s*action\)/,
            /combineReducers|createStore|applyMiddleware/,
        ],
        antipatterns: [],
        confidence: 0.93
    },
    "Vuex": {
        patterns: [
            /vuex|__VUEX__|\$store\.state|\$store\.dispatch|new Vuex\.Store/,
        ],
        antipatterns: [],
        confidence: 0.94
    },
    "MobX": {
        patterns: [
            /mobx|@observable|makeObservable|reaction\(|autorun\(/,
        ],
        antipatterns: [],
        confidence: 0.90
    },
    "Pinia": {
        patterns: [
            /pinia|defineStore|usePinia|storeToRefs/,
        ],
        antipatterns: [],
        confidence: 0.92
    },
    
    // Backend/Server Frameworks
    "Express.js": {
        patterns: [
            /express\(\)|app\.(?:get|post|put|delete|use)\s*\(|new Express\(\)/,
            /middleware|req\.body|res\.json|res\.send|app\.listen/,
        ],
        antipatterns: [],
        confidence: 0.95
    },
    "Fastify": {
        patterns: [
            /fastify\(\)|fastify\.(?:get|post|put|delete)|await fastify\.listen/,
        ],
        antipatterns: [],
        confidence: 0.93
    },
    "NestJS": {
        patterns: [
            /NestFactory|@Module|@Controller|@Get\(|@Post\(|@Injectable/,
        ],
        antipatterns: [],
        confidence: 0.96
    },
    "Koa": {
        patterns: [
            /new Koa\(\)|ctx\.body|ctx\.request|ctx\.response|app\.listen/,
        ],
        antipatterns: [],
        confidence: 0.90
    },
    "Django": {
        patterns: [
            /django\.|from django|{% ?if|{% ?for|{% ?block|{% ?csrf_token/,
        ],
        antipatterns: [],
        confidence: 0.92
    },
    "Flask": {
        patterns: [
            /Flask|@app\.route|render_template|jsonify|request\.args/,
        ],
        antipatterns: [],
        confidence: 0.90
    },
    
    // Cloud & Hosting
    "AWS": {
        patterns: [
            /\.amazonaws\.com|aws-sdk|AWS\.|@aws-sdk|s3\.amazonaws/,
        ],
        antipatterns: [],
        confidence: 0.95
    },
    "Firebase": {
        patterns: [
            /firebase\.|firebaseapp\.com|getFirestore|getAuth|sendPasswordResetEmail/,
        ],
        antipatterns: [],
        confidence: 0.97
    },
    "Azure": {
        patterns: [
            /\.azure\.com|Azure\.|azure-storage|@azure\/|Microsoft\.Azure/,
        ],
        antipatterns: [],
        confidence: 0.93
    },
    "Google Cloud": {
        patterns: [
            /googleapis\.com|@google-cloud|cloud\.google\.com|gcloud/,
        ],
        antipatterns: [],
        confidence: 0.90
    },
    "Cloudflare": {
        patterns: [
            /cloudflare\.com|cf-ray|CF-RAY|workers\.cloudflare\.com|wrangler/,
        ],
        antipatterns: [],
        confidence: 0.94
    },
    "Vercel": {
        patterns: [
            /vercel\.app|__VERCEL__|VERCEL_|vercel\.com|zeit\.co/,
        ],
        antipatterns: [],
        confidence: 0.98
    },
    "Netlify": {
        patterns: [
            /netlify\.app|netlify\.com|__NETLIFY__|NETLIFY_FUNCTIONS/,
        ],
        antipatterns: [],
        confidence: 0.96
    },
    "Heroku": {
        patterns: [
            /heroku|herokucdn\.com|herokuapp\.com|dyno(?:s)?/,
        ],
        antipatterns: [],
        confidence: 0.92
    },
    
    // GraphQL & APIs
    "GraphQL": {
        patterns: [
            /graphql|apollo(?:client)?|urql|relay|@apollo\/client/,
            /query\s+\{|mutation\s+\{|subscription\s+\{|__typename/,
        ],
        antipatterns: [],
        confidence: 0.93
    },
    "Apollo": {
        patterns: [
            /apollo|@apollo\/client|ApolloClient|useQuery|useMutation|ApolloProvider/,
        ],
        antipatterns: [],
        confidence: 0.96
    },
    "Relay": {
        patterns: [
            /relay|graphql-relay|useFragment|useQuery|Fragment\$/,
        ],
        antipatterns: [],
        confidence: 0.91
    },
    
    // Testing
    "Jest": {
        patterns: [
            /jest|describe\(|it\(|test\(|expect\(|beforeEach\(|afterEach\(/,
        ],
        antipatterns: [],
        confidence: 0.90
    },
    "Mocha": {
        patterns: [
            /mocha|describe\(|it\(|before\(|after\(|chai\.expect/,
        ],
        antipatterns: ["jest"],
        confidence: 0.85
    },
    "Cypress": {
        patterns: [
            /cypress|cy\.visit|cy\.get|cy\.click|cy\.type|e2e/,
        ],
        antipatterns: [],
        confidence: 0.93
    },
    "Vitest": {
        patterns: [
            /vitest|describe\(|it\(|test\(|expect\(|vi\./,
        ],
        antipatterns: [],
        confidence: 0.90
    },
    
    // Monitoring & Analytics
    "Google Analytics": {
        patterns: [
            /gtag\(|google-analytics|ga\(|_gaq\.push|googletagmanager\.com/,
        ],
        antipatterns: [],
        confidence: 0.94
    },
    "Sentry": {
        patterns: [
            /sentry|Sentry\.captureException|@sentry\/|sentry\.io/,
        ],
        antipatterns: [],
        confidence: 0.96
    },
    "Datadog": {
        patterns: [
            /datadog|DD_APPLICATION_|DD_SESSION_|datadoghq\.com/,
        ],
        antipatterns: [],
        confidence: 0.92
    },
    "New Relic": {
        patterns: [
            /newrelic|nr(?:eum)?|newrelic\.com/,
        ],
        antipatterns: [],
        confidence: 0.90
    },
    "Mixpanel": {
        patterns: [
            /mixpanel|mp\.track|mixpanel\.track_links/,
        ],
        antipatterns: [],
        confidence: 0.92
    },
    "Segment": {
        patterns: [
            /segment|analytics\.track|analytics\.identify|segment\.com/,
        ],
        antipatterns: [],
        confidence: 0.91
    },
    "Hotjar": {
        patterns: [
            /hotjar|hj\(|hjid|hjsv|heatmap\.com/,
        ],
        antipatterns: [],
        confidence: 0.93
    },
    
    // Additional Frameworks
    "TypeScript": {
        patterns: [
            /\.ts(x)?:|interface\s+\w+\s*\{|type\s+\w+\s*=|<.*>.*=>/,
        ],
        antipatterns: [],
        confidence: 0.92
    }
};

/**
 * Comprehensive technology stack detection
 */
function detectStack(code) {
    const detections = new Map(); // Store with confidence scores
    const lowerCode = code.toLowerCase();
    
    // Test each technology fingerprint
    for (const [tech, fingerprint] of Object.entries(TECH_FINGERPRINTS)) {
        let matched = false;
        let matchScore = 0;
        
        // Check positive patterns
        for (const pattern of fingerprint.patterns) {
            if (pattern.test(code)) {
                matched = true;
                matchScore += 1;
            }
        }
        
        // Check antipatterns (false positives)
        let hasAntiPattern = false;
        for (const antiPattern of fingerprint.antipatterns) {
            if (lowerCode.includes(antiPattern.toLowerCase())) {
                hasAntiPattern = true;
                break;
            }
        }
        
        // Calculate final confidence
        if (matched && !hasAntiPattern) {
            const confidence = Math.min(
                fingerprint.confidence * (matchScore / fingerprint.patterns.length),
                1.0
            );
            detections.set(tech, confidence);
        }
    }
    
    // Store findings with confidence scores
    let primaryStack = "unknown";
    let maxConfidence = 0;
    
    // Determine primary stack (highest confidence)
    detections.forEach((confidence, tech) => {
        if (confidence > maxConfidence) {
            maxConfidence = confidence;
            primaryStack = tech;
        }
    });
    
    store.stackDetected = primaryStack;
    
    // Store all detections
    detections.forEach((confidence, tech) => {
        if (confidence > 0.7) { // Only store high-confidence detections
            const severity = tech === primaryStack ? 3 : 2;
            store.addFinding(
                "technology",
                `${tech} (confidence: ${(confidence * 100).toFixed(0)}%)`,
                severity,
                "stack_detection",
                `Detected with ${(confidence * 100).toFixed(0)}% confidence`
            );
            store.technologies.add(tech);
        }
    });
    
    return primaryStack;
}

/**
 * Get noise filters based on detected stack
 */
function getNoiseFilters(stack) {
    const filters = {
        "WordPress": [
            "wp-admin", "wp-content", "wp-includes", "/wp-json/",
            "jquery", "wpadminbar"
        ],
        "React": [
            "react", "webpack", "react-dom", "react.development"
        ],
        "Vue.js": [
            "vue", "__vue__"
        ],
        "Angular": [
            "angular", "ng-"
        ],
        "jQuery": [
            "jquery", "$.ajax", "$.get", "$.post"
        ]
    };
    
    return filters[stack] || [];
}

/**
 * Get version information if available
 */
function detectVersion(code, technology) {
    const versionPatterns = {
        "React": [
            /React\.version\s*=\s*['"]([^'"]+)['"]/,
            /react@([0-9.]+)/,
            /version.*:.*['"]([0-9.]+)['"]/
        ],
        "Vue.js": [
            /Vue\.version\s*=\s*['"]([^'"]+)['"]/,
            /vue@([0-9.]+)/
        ],
        "Angular": [
            /angular\.version\s*=\s*['"]([^'"]+)['"]/,
            /angular@([0-9.]+)/
        ],
        "Next.js": [
            /__NEXT_VERSION__\s*[=:]\s*['"]([^'"]+)['"]/,
            /next@([0-9.]+)/
        ]
    };
    
    const patterns = versionPatterns[technology] || [];
    for (const pattern of patterns) {
        const match = code.match(pattern);
        if (match && match[1]) {
            return match[1];
        }
    }
    
    return null;
}

/**
 * Enhanced detection with additional confidence metrics
 */
function enhancedDetect(code) {
    return {
        primaryStack: detectStack(code),
        allDetections: new Map(),
        versionInfo: {}
    };
}

module.exports = {
    detectStack,
    getNoiseFilters,
    detectVersion,
    enhancedDetect,
    TECH_FINGERPRINTS
};
