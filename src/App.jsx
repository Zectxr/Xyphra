import React, { useState } from 'react';
import axios from 'axios';
import './App.css';
import brandMarkUrl from '../virus-none-svgrepo-com.svg';

const API_KEY = 'a68ac31cfb5385b86565aa3832dfd762025e665ab909a53caf4bc91a629e17b5'
const XYPHRA_API_URL = 'https://www.virustotal.com/api/v3';
const GROQ_API_KEY = import.meta.env.VITE_GROQ_API_KEY;
const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';

const CONTACT_LINKS = {
  github: 'https://github.com/Zectxr',
  linkedin: 'https://www.linkedin.com/in/edmund-lazaro-36b375399/',
  website: 'https://edmundnimeslazaro.netlify.app/#home',
  phone: 'tel:09762320212'
};

function App() {
  const [url, setUrl] = useState('');
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('file');
  const [behaviorReports, setBehaviorReports] = useState(null);
  const [loadingBehavior, setLoadingBehavior] = useState(false);
  const [fileId, setFileId] = useState(null);
  const [summary, setSummary] = useState(null);
  const [loadingSummary, setLoadingSummary] = useState(false);
  const [summarySource, setSummarySource] = useState(null);

  const scanURL = async (e) => {
    e.preventDefault();
    if (!API_KEY) {
      setError('Missing VirusTotal API key. Create a .env with VITE_VT_API_KEY and restart the dev server.');
      return;
    }
    if (!url) {
      setError('Please enter a URL');
      return;
    }

    setLoading(true);
    setError('');
    setResults(null);
    setBehaviorReports(null);
    setFileId(null);
    setSummary(null);
    setSummarySource(null);

    try {
      // Submit URL for scanning
      const formData = new FormData();
      formData.append('url', url);

      const response = await axios.post(
        `${XYPHRA_API_URL}/urls`,
        formData,
        {
          headers: {
            'x-apikey': API_KEY,
          },
        }
      );

      const analysisId = response.data.data.id;

      // Wait a bit before checking results
      await new Promise((resolve) => setTimeout(resolve, 3000));

      // Get scan results
      const analysisResponse = await axios.get(
        `${XYPHRA_API_URL}/analyses/${analysisId}`,
        {
          headers: {
            'x-apikey': API_KEY,
          },
        }
      );

      const attrs = analysisResponse.data.data.attributes;
      setResults(attrs);
      setLoading(false);

      // Automatically generate an AI summary for URL scans
      await generateUrlSummary(attrs, url);
    } catch (err) {
      setError(err.response?.data?.error?.message || 'Error scanning URL');
      setLoading(false);
    }
  };

  const scanFile = async (e) => {
    e.preventDefault();
    if (!API_KEY) {
      setError('Missing VirusTotal API key. Create a .env with VITE_VT_API_KEY and restart the dev server.');
      return;
    }
    if (!file) {
      setError('Please select a file');
      return;
    }

    if (file.size > 32 * 1024 * 1024) {
      setError('File size exceeds 32MB limit');
      return;
    }

    setLoading(true);
    setError('');
    setResults(null);
    setBehaviorReports(null);
    setFileId(null);
    setSummary(null);
    setSummarySource(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await axios.post(
        `${XYPHRA_API_URL}/files`,
        formData,
        {
          headers: {
            'x-apikey': API_KEY,
            'Content-Type': 'multipart/form-data',
          },
        }
      );

      const analysisId = response.data.data.id;

      // Wait for analysis to complete
      await new Promise((resolve) => setTimeout(resolve, 5000));

      // Get scan results
      const analysisResponse = await axios.get(
        `${XYPHRA_API_URL}/analyses/${analysisId}`,
        {
          headers: {
            'x-apikey': API_KEY,
          },
        }
      );

      setResults(analysisResponse.data.data.attributes);
      
      // Extract file ID (SHA-256) for behavior reports
      const fileSha256 = analysisResponse.data.meta?.file_info?.sha256;
      if (fileSha256) {
        setFileId(fileSha256);
      }
      
      setLoading(false);
    } catch (err) {
      setError(err.response?.data?.error?.message || 'Error scanning file');
      setLoading(false);
    }
  };

  const getBehaviorReports = async () => {
    if (!fileId) {
      setError('No file ID available for behavior reports');
      return;
    }

    setLoadingBehavior(true);
    setError('');
    setBehaviorReports(null);
    setSummary(null);

    try {
      const response = await axios.get(
        `${XYPHRA_API_URL}/files/${fileId}/behaviours`,
        {
          headers: {
            'x-apikey': API_KEY,
          },
        }
      );

      const behaviorData = response.data.data;
      setBehaviorReports(behaviorData);
      setLoadingBehavior(false);
      
      // Automatically generate summary after getting behavior reports
      if (behaviorData && behaviorData.length > 0) {
        await generateSummary(behaviorData);
      }
    } catch (err) {
      setError(err.response?.data?.error?.message || 'Error fetching behavior reports');
      setLoadingBehavior(false);
    }
  };

  const generateSummary = async (behaviorData) => {
    setLoadingSummary(true);
    try {
      if (!GROQ_API_KEY) {
        setSummary(null);
        setError('Missing Groq API key. Create a .env with VITE_GROQ_API_KEY and restart the dev server.');
        setLoadingSummary(false);
        return;
      }
      // Prepare data for summarization
      const summaryData = behaviorData.map((report, index) => {
        const attrs = report.attributes || {};
        return {
          sandbox: index + 1,
          sandbox_name: attrs.sandbox_name || 'Unknown',
          verdict: attrs.verdict || 'unknown',
          processes_created: attrs.processes_created?.length || 0,
          files_written: attrs.files_written?.length || 0,
          files_deleted: attrs.files_deleted?.length || 0,
          registry_keys_set: attrs.registry_keys_set?.length || 0,
          registry_keys_deleted: attrs.registry_keys_deleted?.length || 0,
          dns_lookups: attrs.dns_lookups?.length || 0,
          ip_traffic: attrs.ip_traffic?.length || 0,
          http_conversations: attrs.http_conversations?.length || 0,
          tags: attrs.tags || [],
          has_html_report: attrs.has_html_report || false,
          has_pcap: attrs.has_pcap || false
        };
      });

      const completionResponse = await axios.post(
        GROQ_API_URL,
        {
          model: 'llama-3.3-70b-versatile',
          messages: [
            {
              role: 'system',
              content:
                'You are a cybersecurity expert analyzing malware behavior reports from sandbox environments. Provide clear, concise summaries focusing on threats, suspicious activities, and safety recommendations. Keep your response under 200 words.'
            },
            {
              role: 'user',
              content: `Analyze these sandbox behavior reports and provide a security summary:\n\n${JSON.stringify(
                summaryData,
                null,
                2
              )}\n\nProvide: 1) Overall threat assessment, 2) Key malicious behaviors detected, 3) Recommendation for the user.`
            }
          ],
          temperature: 0.7,
          max_tokens: 500
        },
        {
          headers: {
            Authorization: `Bearer ${GROQ_API_KEY}`,
            'Content-Type': 'application/json'
          }
        }
      );

      const aiSummary =
        completionResponse.data?.choices?.[0]?.message?.content || 'Unable to generate summary.';
      setSummary(aiSummary);
      setSummarySource('file');
      setLoadingSummary(false);
    } catch (err) {
      console.error('Error generating summary:', err);
      setError('Error generating AI summary');
      setLoadingSummary(false);
    }
  };

  const generateUrlSummary = async (analysisAttributes, targetUrl) => {
    setLoadingSummary(true);
    try {
      if (!GROQ_API_KEY) {
        setSummary(null);
        setError('Missing Groq API key. Create a .env with VITE_GROQ_API_KEY and restart the dev server.');
        setLoadingSummary(false);
        return;
      }

      const stats = analysisAttributes?.stats || {};
      const engineResults = analysisAttributes?.results || {};

      const detections = Object.entries(engineResults)
        .filter(([, r]) => r?.category === 'malicious' || r?.category === 'suspicious')
        .slice(0, 15)
        .map(([engine, r]) => ({
          engine,
          category: r?.category,
          result: r?.result,
          method: r?.method
        }));

      const urlSummaryData = {
        url: targetUrl,
        stats: {
          malicious: stats.malicious || 0,
          suspicious: stats.suspicious || 0,
          harmless: stats.harmless || 0,
          undetected: stats.undetected || 0
        },
        flagged_by: detections
      };

      const completionResponse = await axios.post(
        GROQ_API_URL,
        {
          model: 'llama-3.3-70b-versatile',
          messages: [
            {
              role: 'system',
              content:
                'You are a cybersecurity assistant. Summarize VirusTotal URL scan findings clearly and conservatively. Keep under 160 words. If detections are low-confidence, say so.'
            },
            {
              role: 'user',
              content: `Summarize this VirusTotal URL analysis JSON and give: 1) Risk level (Low/Medium/High), 2) Why, 3) Safe next steps for the user.\n\n${JSON.stringify(
                urlSummaryData,
                null,
                2
              )}`
            }
          ],
          temperature: 0.5,
          max_tokens: 350
        },
        {
          headers: {
            Authorization: `Bearer ${GROQ_API_KEY}`,
            'Content-Type': 'application/json'
          }
        }
      );

      const aiSummary =
        completionResponse.data?.choices?.[0]?.message?.content || 'Unable to generate summary.';
      setSummary(aiSummary);
      setSummarySource('url');
      setLoadingSummary(false);
    } catch (err) {
      console.error('Error generating URL summary:', err);
      setError('Error generating AI summary');
      setLoadingSummary(false);
    }
  };

  const renderResults = () => {
    if (!results) return null;

    const stats = results.stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const undetected = stats.undetected || 0;
    const harmless = stats.harmless || 0;
    const total = malicious + suspicious + undetected + harmless;

    const isSafe = malicious === 0 && suspicious === 0;

    return (
      <div className={`results ${isSafe ? 'safe' : 'danger'}`}>
        <h2>{isSafe ? 'Clean' : 'Threat detected'}</h2>
        <div className="stats">
          <div className="stat-item">
            <span className="stat-label">Malicious:</span>
            <span className="stat-value danger-text">{malicious}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Suspicious:</span>
            <span className="stat-value warning-text">{suspicious}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Undetected:</span>
            <span className="stat-value">{undetected}</span>
          </div>
          <div className="stat-item">
            <span className="stat-label">Harmless:</span>
            <span className="stat-value safe-text">{harmless}</span>
          </div>
          <div className="stat-item total">
            <span className="stat-label">Total Engines:</span>
            <span className="stat-value">{total}</span>
          </div>
        </div>
        <div className="progress-bar">
          <div
            className="progress-fill malicious"
            style={{ width: `${(malicious / total) * 100}%` }}
          />
          <div
            className="progress-fill suspicious"
            style={{ width: `${(suspicious / total) * 100}%` }}
          />
          <div
            className="progress-fill harmless"
            style={{ width: `${(harmless / total) * 100}%` }}
          />
        </div>

        {activeTab === 'url' && loadingSummary && (
          <div className="summary-loading">
            <div className="spinner-small"></div>
            <p>Generating AI summary...</p>
          </div>
        )}

        {activeTab === 'url' && summarySource === 'url' && summary && (
          <div className="ai-summary">
            <div className="summary-header">
              <h3>AI Security Analysis</h3>
            </div>
            <div className="summary-content">
              {summary.split('\n').map((line, idx) => (
                <p key={idx}>{line}</p>
              ))}
            </div>
          </div>
        )}

        {fileId && activeTab === 'file' && (
          <div className="behavior-section">
            <button 
              onClick={getBehaviorReports} 
              className="btn-secondary"
              disabled={loadingBehavior}
            >
              {loadingBehavior ? 'Loading...' : 'View Behavior Reports'}
            </button>
          </div>
        )}
      </div>
    );
  };

  const renderBehaviorReports = () => {
    if (!behaviorReports || behaviorReports.length === 0) return null;

    return (
      <div className="behavior-reports">
        <h2>Sandbox behavior analysis</h2>
        <p className="behavior-count">Found {behaviorReports.length} sandbox report(s)</p>
        
        {/* AI Summary Section */}
        {loadingSummary && (
          <div className="summary-loading">
            <div className="spinner-small"></div>
            <p>Generating AI summary...</p>
          </div>
        )}
        
        {summary && (
          <div className="ai-summary">
            <div className="summary-header">
              <h3>AI Security Analysis</h3>
            </div>
            <div className="summary-content">
              {summary.split('\n').map((line, idx) => (
                <p key={idx}>{line}</p>
              ))}
            </div>
          </div>
        )}
        
        {behaviorReports.map((report, index) => {
          const attrs = report.attributes || {};
          
          return (
            <div key={report.id || index} className="behavior-report-card">
              <div className="report-header">
                <h3>Sandbox #{index + 1}</h3>
                {attrs.sandbox_name && (
                  <span className="sandbox-name">{attrs.sandbox_name}</span>
                )}
              </div>
              
              <div className="report-details">
                {attrs.analysis_date && (
                  <div className="detail-item">
                    <strong>Analysis Date:</strong> {new Date(attrs.analysis_date * 1000).toLocaleString()}
                  </div>
                )}
                
                {attrs.has_html_report && (
                  <div className="detail-item">
                    <span className="badge badge-info">HTML Report Available</span>
                  </div>
                )}
                
                {attrs.has_pcap && (
                  <div className="detail-item">
                    <span className="badge badge-info">PCAP Available</span>
                  </div>
                )}

                {attrs.verdict && (
                  <div className="detail-item">
                    <strong>Verdict:</strong> 
                    <span className={`verdict verdict-${attrs.verdict}`}>
                      {attrs.verdict}
                    </span>
                  </div>
                )}

                {attrs.processes_created && attrs.processes_created.length > 0 && (
                  <div className="detail-item">
                    <strong>Processes Created:</strong> {attrs.processes_created.length}
                  </div>
                )}

                {attrs.files_written && attrs.files_written.length > 0 && (
                  <div className="detail-item">
                    <strong>Files Written:</strong> {attrs.files_written.length}
                  </div>
                )}

                {attrs.files_deleted && attrs.files_deleted.length > 0 && (
                  <div className="detail-item">
                    <strong>Files Deleted:</strong> {attrs.files_deleted.length}
                  </div>
                )}

                {attrs.registry_keys_set && attrs.registry_keys_set.length > 0 && (
                  <div className="detail-item">
                    <strong>Registry Keys Set:</strong> {attrs.registry_keys_set.length}
                  </div>
                )}

                {attrs.registry_keys_deleted && attrs.registry_keys_deleted.length > 0 && (
                  <div className="detail-item">
                    <strong>Registry Keys Deleted:</strong> {attrs.registry_keys_deleted.length}
                  </div>
                )}

                {attrs.dns_lookups && attrs.dns_lookups.length > 0 && (
                  <div className="detail-item">
                    <strong>DNS Lookups:</strong> {attrs.dns_lookups.length}
                  </div>
                )}

                {attrs.ip_traffic && attrs.ip_traffic.length > 0 && (
                  <div className="detail-item">
                    <strong>IP Traffic:</strong> {attrs.ip_traffic.length} connection(s)
                  </div>
                )}

                {attrs.http_conversations && attrs.http_conversations.length > 0 && (
                  <div className="detail-item">
                    <strong>HTTP Conversations:</strong> {attrs.http_conversations.length}
                  </div>
                )}
              </div>

              {attrs.tags && attrs.tags.length > 0 && (
                <div className="tags-section">
                  <strong>Tags:</strong>
                  <div className="tags">
                    {attrs.tags.map((tag, idx) => (
                      <span key={idx} className="tag">{tag}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div className="appRoot">
      <div className="scene" aria-hidden="true">
        <div className="sceneLayer sceneLayer--sky" />
        <div className="sceneLayer sceneLayer--stars" />
        <div className="sceneLayer sceneLayer--horizon" />
      </div>

      <div className="appShell">
        <div className="container">
          <div className="brand" aria-label="Brand header">
            <img className="brandMark" src={brandMarkUrl} alt="" aria-hidden="true" />
            <div className="brandName">Xyphra</div>
          </div>
          <p className="subtitle">
            AI-powered analysis of files, domains, IPs, and URLs to detect malware, phishing, and active security threats.
          </p>

          <div className="tabs" role="tablist" aria-label="Scan modes">
            <button
              className={`tab ${activeTab === 'file' ? 'active' : ''}`}
              onClick={() => setActiveTab('file')}
              type="button"
              role="tab"
              aria-selected={activeTab === 'file'}
            >
              FILE
            </button>
            <button
              className={`tab ${activeTab === 'url' ? 'active' : ''}`}
              onClick={() => setActiveTab('url')}
              type="button"
              role="tab"
              aria-selected={activeTab === 'url'}
            >
              URL
            </button>
          </div>

          {activeTab === 'url' && (
            <form onSubmit={scanURL} className="scan-form">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter URL"
                className="input"
                disabled={loading}
              />
              <button type="submit" className="btn-primary" disabled={loading}>
                {loading ? 'Scanning…' : 'Scan'}
              </button>
            </form>
          )}

          {activeTab === 'file' && (
            <form onSubmit={scanFile} className="scan-form">
              <div className="dropzone">
                <div className="dropIcon" aria-hidden="true" />

                <div className="file-input-wrapper">
                  <input
                    type="file"
                    onChange={(e) => setFile(e.target.files[0])}
                    className="file-input"
                    id="file-upload"
                    disabled={loading}
                  />
                  <label htmlFor="file-upload" className="file-label">
                    {file ? file.name : 'Choose file'}
                  </label>
                </div>

                <div className="dropHint">Max size 32MB</div>
              </div>

              <button type="submit" className="btn-primary" disabled={loading}>
                {loading ? 'Scanning…' : 'Scan'}
              </button>
            </form>
          )}

        {loading && (
          <div className="loading">
            <div className="spinner"></div>
            <p>Scanning in progress, please wait...</p>
          </div>
        )}

        {error && <div className="error">{error}</div>}

        {renderResults()}
        
          {renderBehaviorReports()}

          <footer className="footer" aria-label="Footer">
            <div className="footerLinks">
              <a className="footerLink" href={CONTACT_LINKS.github} target="_blank" rel="noreferrer">
                GitHub
              </a>
              <a className="footerLink" href={CONTACT_LINKS.linkedin} target="_blank" rel="noreferrer">
                LinkedIn
              </a>
                <a className="footerLink" href={CONTACT_LINKS.website} target="_blank" rel="noreferrer">
                  Website
              </a>
            </div>
          </footer>
        </div>
      </div>
    </div>
  );
}

export default App;
