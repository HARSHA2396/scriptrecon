import { useState, useCallback, useEffect } from 'react';
import { Editor } from '@monaco-editor/react';
import { Activity, ShieldAlert, Zap, Layers, CheckCircle2, Lock, Route, UploadCloud, Globe, Code2 } from 'lucide-react';
import { useDropzone } from 'react-dropzone';
import axios from 'axios';
import * as jsAnalyzerCore from '@js-analyzer/core';
const { analyzeCode } = jsAnalyzerCore;
import './index.css';

const DEFAULT_CODE = `// Penetration Testing & Vulnerability Sandbox
// Deep scan for XSS, logic flaws, and hardcoded secrets

const config = {
  // Critical: Hardcoded GitHub Token
  api_key: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  // Critical: Cryptographically weak RNG
  sessionToken: Math.random().toString()
};

// Endpoint Discovery
axios.post('https://api.internal-corp.local/v1/auth/login', {
   user: "admin",
   pass: "password"
});

function handleData(req, res) {
  // Vulnerability: Insecure XSS parsing
  document.getElementById('profile').innerHTML = req.query.name;
    
  // Vulnerability: Weak cryptographic algorithm
  const hash = md5(req.query.password);
  
  // Vulnerability: Weak equality on sensitive authentication check
  if (req.query.password == "super_secret_backdoor") {
     validateLogin(req.query.password);
  }
}

// Deep Nesting (Code Quality)
for(let x=0; x<10; x++) {
  if (req) {
     if (res) {
        if (session) {
            console.log("Deep");
        }
     }
  }
}
`;

function App() {
  const [code, setCode] = useState(DEFAULT_CODE);
  const [analysis, setAnalysis] = useState<any>({ complexity: 0, issues: [], endpoints: [] });
  const [error, setError] = useState<string | null>(null);
  
  // Advanced Input States
  const [inputMode, setInputMode] = useState<'editor' | 'upload' | 'url'>('editor');
  const [urlInput, setUrlInput] = useState('');
  const [isFetchingUrl, setIsFetchingUrl] = useState(false);

  const runAnalysis = useCallback((source: string) => {
    try {
      setError(null);
      const result = analyzeCode(source);
      const priorityWeights: Record<string, number> = { security: 5, auth: 4, endpoint: 3, performance: 2, quality: 1 };
      result.issues.sort((a: any, b: any) => priorityWeights[b.type] - priorityWeights[a.type]);
      setAnalysis(result);
    } catch (err: any) {
      setError(err.message || 'Syntax error during parsing.');
      setAnalysis({ complexity: 0, issues: [], endpoints: [] });
    }
  }, []);

  // Dropzone Setup
  const onDrop = useCallback((acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = e.target?.result as string;
        setCode(text);
        runAnalysis(text);
        setInputMode('editor'); // Switch back to editor to view code
      };
      reader.readAsText(file);
    }
  }, [runAnalysis]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ 
      onDrop,
      accept: { 'text/javascript': ['.js', '.jsx', '.ts', '.tsx'] },
      maxFiles: 1
  });

  // URL Fetching
  const handleUrlScan = async () => {
      if (!urlInput) return;
      setIsFetchingUrl(true);
      setError(null);
      try {
          // Note: In a browser, standard URL fetching hits CORS. 
          // We assume testing against CORS friendly endpoints or localhost, 
          // alternatively a CORS proxy would be needed here for raw production use.
          const res = await axios.get(urlInput);
          if (typeof res.data !== 'string') {
               throw new Error('Target did not return raw text/javascript payload.');
          }
          setCode(res.data);
          runAnalysis(res.data);
          setInputMode('editor');
      } catch (err: any) {
          setError(err.message || 'Failed to fetch external URL.');
      } finally {
          setIsFetchingUrl(false);
      }
  };

  useEffect(() => {
    runAnalysis(DEFAULT_CODE);
  }, [runAnalysis]);

  const handleEditorChange = (value: string | undefined) => {
    if (value !== undefined) {
      setCode(value);
      runAnalysis(value);
    }
  };

  const getIconForType = (type: string) => {
    switch (type) {
      case 'security': return <ShieldAlert size={16} color="var(--accent-danger)" />;
      case 'auth': return <Lock size={16} color="var(--accent-secondary)" />;
      case 'endpoint': return <Route size={16} color="#14b8a6" />;
      case 'performance': return <Zap size={16} color="var(--accent-warning)" />;
      case 'quality': return <Activity size={16} color="var(--accent-primary)" />;
      default: return null;
    }
  };

  return (
    <div className="app-container">
      <header className="header">
        <ShieldAlert size={28} color="var(--accent-danger)" />
        <h1>JS Recon Analyzer PRO</h1>
        
        <div className="input-toggles" style={{ marginLeft: 'auto', display: 'flex', gap: '0.5rem' }}>
             <button className={`toggle-btn ${inputMode === 'editor' ? 'active' : ''}`} onClick={() => setInputMode('editor')}><Code2 size={16}/> Editor</button>
             <button className={`toggle-btn ${inputMode === 'upload' ? 'active' : ''}`} onClick={() => setInputMode('upload')}><UploadCloud size={16}/> Upload</button>
             <button className={`toggle-btn ${inputMode === 'url' ? 'active' : ''}`} onClick={() => setInputMode('url')}><Globe size={16}/> URL Scan</button>
        </div>
      </header>

      <main className="main-content">
        <section className="editor-section">
          {inputMode === 'editor' && (
              <>
                  <div className="editor-header">
                    <span>Target Script Payload</span>
                    <span style={{color: error ? 'var(--accent-danger)' : 'var(--accent-success)'}}>
                        {error ? 'AST Parse Error' : 'Aggressive Scanning Active'}
                    </span>
                  </div>
                  <div className="monaco-container">
                    <Editor
                      height="100%"
                      defaultLanguage="javascript"
                      theme="vs-dark"
                      value={code}
                      onChange={handleEditorChange}
                      options={{
                        minimap: { enabled: false },
                        fontSize: 14,
                        fontFamily: "'Fira Code', monospace",
                        lineHeight: 24,
                        padding: { top: 16 },
                        scrollBeyondLastLine: false,
                        smoothScrolling: true,
                        cursorBlinking: "smooth",
                        cursorSmoothCaretAnimation: "on"
                      }}
                    />
                  </div>
              </>
          )}

          {inputMode === 'upload' && (
              <div className="glass-card" style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', border: '2px dashed var(--border-color)' }}>
                  <div {...getRootProps()} style={{ cursor: 'pointer', textAlign: 'center', padding: '3rem' }}>
                    <input {...getInputProps()} />
                    <UploadCloud size={64} style={{ marginBottom: '1rem', color: isDragActive ? 'var(--accent-primary)' : 'var(--text-muted)' }} />
                    {isDragActive ? <p>Drop payload here...</p> : <p>Drag & drop a JS/TS file here, or click to select.</p>}
                  </div>
              </div>
          )}

          {inputMode === 'url' && (
              <div className="glass-card" style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: '2rem' }}>
                  <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}><Globe size={20} /> Remote URL Scanner</h2>
                  <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem' }}>Fetch and analyze live JavaScript files directly from a target domain. (Note: May require CORS to be enabled on target).</p>
                  
                  <div style={{ display: 'flex', gap: '1rem' }}>
                      <input 
                          type="text" 
                          value={urlInput}
                          onChange={(e) => setUrlInput(e.target.value)}
                          placeholder="https://example.com/assets/main.js" 
                          style={{ flex: 1, padding: '0.75rem', borderRadius: '4px', border: '1px solid var(--border-color)', background: 'var(--bg-lighter)', color: 'var(--text-main)', fontFamily: 'monospace' }}
                      />
                      <button 
                          onClick={handleUrlScan} 
                          disabled={isFetchingUrl || !urlInput}
                          style={{ padding: '0.75rem 1.5rem', background: 'var(--accent-primary)', color: 'white', border: 'none', borderRadius: '4px', cursor: isFetchingUrl ? 'wait' : 'pointer', fontWeight: 600 }}
                      >
                          {isFetchingUrl ? 'Fetching...' : 'Engage Scanner'}
                      </button>
                  </div>
                  {error && inputMode === 'url' && <div style={{ color: 'var(--accent-danger)', marginTop: '1rem' }}>{error}</div>}
              </div>
          )}
        </section>

        <section className="results-section">
          <div className="glass-card">
            <h2 style={{ marginBottom: '1.2rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Layers size={20} /> Recon Overview
            </h2>
            
            <div className="stat-grid" style={{ gridTemplateColumns: '1fr 1fr 1fr' }}>
              <div className="stat-box">
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Complexity</span>
                <span className="stat-value" style={{ color: 'var(--text-main)' }}>{analysis.complexity}</span>
              </div>
              <div className="stat-box">
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Found Endpoints</span>
                <span className="stat-value" style={{ color: (analysis.endpoints?.length || 0) > 0 ? '#14b8a6' : 'var(--text-main)' }}>
                  {analysis.endpoints?.length || 0}
                </span>
              </div>
              <div className="stat-box">
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Threat Incidents</span>
                <span className="stat-value" style={{ color: (analysis.issues?.length || 0) > 0 ? 'var(--accent-danger)' : 'var(--accent-success)' }}>
                  {analysis.issues?.length || 0}
                </span>
              </div>
            </div>
          </div>

          <div className="glass-card" style={{ flex: 1, overflowY: 'auto' }}>
            <h2 style={{ marginBottom: '1.2rem' }}>Threat Intelligence Report</h2>
            
            {error ? (
              <div className="issue-item security" style={{ animationDelay: '0ms' }}>
                <div className="issue-header">
                  <span style={{ color: 'var(--accent-danger)'}}>Syntax Error</span>
                </div>
                <div className="issue-message" style={{fontFamily: 'monospace'}}>{error}</div>
              </div>
            ) : analysis.issues && analysis.issues.length > 0 ? (
              <div className="issue-list">
                {analysis.issues.map((issue: any, idx: number) => (
                  <div key={idx} className={`issue-item ${issue.type}`} style={{ animationDelay: `${idx * 50}ms` }}>
                    <div className="issue-header">
                       <span style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                          {getIconForType(issue.type)} {issue.type.toUpperCase()}
                       </span>
                       <span>Line {issue.line}</span>
                    </div>
                    <div className="issue-message" style={{ fontWeight: issue.type === 'security' || issue.type === 'auth' ? '600' : '400'}}>{issue.message}</div>
                  </div>
                ))}
              </div>
            ) : (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem', color: 'var(--text-muted)', marginTop: '2rem' }}>
                    <CheckCircle2 size={48} color="var(--accent-success)" opacity={0.5} />
                    <p>No attack vectors identified.</p>
                </div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;
