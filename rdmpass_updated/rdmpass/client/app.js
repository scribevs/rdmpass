/* rdmpass frontend
 *
 * This React app provides an interactive interface for generating
 * completely random passwords based on mouse movement entropy.  Users
 * select the desired number of mouse movements, password length and
 * character classes, and the app collects entropy from the cursor
 * coordinates and timestamps.  Once enough data is collected, a
 * SHA‑256 digest of the movement data is taken to form a 256‑bit
 * seed, which is sent to the backend along with the selected
 * settings.  The resulting password is displayed to the user with
 * an option to copy it to the clipboard.  All state transitions
 * occur client‑side, giving immediate feedback and ensuring that no
 * raw mouse movement data ever leaves the browser.
 */

const { useState, useEffect, useRef } = React;

function App() {
  // Configuration options exposed to the user
  const [requiredMoves, setRequiredMoves] = useState(250);
  const [passwordLength, setPasswordLength] = useState(16);
  const [includeLowercase, setIncludeLowercase] = useState(true);
  const [includeUppercase, setIncludeUppercase] = useState(true);
  const [includeNumbers, setIncludeNumbers] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);
  const [includeExtendedLatin, setIncludeExtendedLatin] = useState(false);
  const [customCharacters, setCustomCharacters] = useState('');
  const [requireEachSelected, setRequireEachSelected] = useState(false);

  // State for entropy collection
  const [collecting, setCollecting] = useState(false);
  const [mouseCount, setMouseCount] = useState(0);
  const [entropy, setEntropy] = useState(null);
  const [progress, setProgress] = useState(0);
  const movementRef = useRef([]);
  const hasComputedEntropy = useRef(false);

  // Output from backend
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Start collecting mouse movements
  const startCollection = () => {
    // reset states
    setPassword('');
    setEntropy(null);
    movementRef.current = [];
    hasComputedEntropy.current = false;
    setMouseCount(0);
    setProgress(0);
    setCollecting(true);
    setError(null);
  };

  // Reset everything including settings back to defaults
  const resetAll = () => {
    setRequiredMoves(250);
    setPasswordLength(16);
    setIncludeLowercase(true);
    setIncludeUppercase(true);
    setIncludeNumbers(true);
    setIncludeSymbols(true);
    setIncludeExtendedLatin(false);
    setCustomCharacters('');
    setRequireEachSelected(false);
    setCollecting(false);
    setPassword('');
    setEntropy(null);
    movementRef.current = [];
    setMouseCount(0);
    setProgress(0);
    hasComputedEntropy.current = false;
    setLoading(false);
    setError(null);
  };

  // Monitor mouse movements when collecting is active
  useEffect(() => {
    if (!collecting) return;
    const handleMove = (e) => {
      // Avoid capturing events once we've reached the required number
      if (movementRef.current.length >= requiredMoves) return;
      const now = performance.now();
      // Record client coordinates and timestamp
      movementRef.current.push({ x: e.clientX, y: e.clientY, t: now });
      const count = movementRef.current.length;
      setMouseCount(count);
      setProgress(Math.min(1, count / requiredMoves));
      if (count >= requiredMoves && !hasComputedEntropy.current) {
        hasComputedEntropy.current = true;
        setCollecting(false);
        computeEntropy(movementRef.current);
      }
    };
    window.addEventListener('mousemove', handleMove);
    return () => {
      window.removeEventListener('mousemove', handleMove);
    };
  }, [collecting, requiredMoves]);

  /**
   * Compute a SHA‑256 digest over the recorded mouse movement data
   * and store it as a base64 string.  The digest is taken over a
   * simple string concatenation of the recorded coordinates and
   * timestamps separated by semicolons.  This ensures that the
   * entropy is derived directly from the unpredictable movement
   * pattern of the user.
   *
   * @param {Array} movements
   */
  async function computeEntropy(movements) {
    try {
      let dataStr = '';
      // Compose a deterministic string representation of the movements
      for (const m of movements) {
        dataStr += `${m.x.toFixed(2)},${m.y.toFixed(2)},${m.t.toFixed(2)};`;
      }
      const encoder = new TextEncoder();
      const dataBuf = encoder.encode(dataStr);
      const hashBuf = await crypto.subtle.digest('SHA-256', dataBuf);
      const hashArray = Array.from(new Uint8Array(hashBuf));
      const hashString = String.fromCharCode.apply(null, hashArray);
      const base64 = btoa(hashString);
      setEntropy(base64);
    } catch (err) {
      setError('Failed to compute entropy: ' + err.message);
    }
  }

  /**
   * Send the collected entropy and user settings to the backend to
   * generate a password.  Handles the asynchronous fetch and
   * updates component state accordingly.
   */
  const generatePassword = async () => {
    if (!entropy) return;
    setLoading(true);
    setError(null);
    try {
      const settings = {
        length: passwordLength,
        includeLowercase,
        includeUppercase,
        includeNumbers,
        includeSymbols,
        includeExtendedLatin,
        customCharacters: customCharacters || '',
        requireEachSelected,
      };
      const resp = await fetch('/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entropy, settings }),
      });
      if (!resp.ok) {
        const errResp = await resp.json().catch(() => ({}));
        throw new Error(errResp.error || 'Request failed');
      }
      const json = await resp.json();
      if (json.password) {
        setPassword(json.password);
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  /**
   * Copy the generated password to the clipboard.  Uses the
   * asynchronous clipboard API when available.
   */
  const copyPassword = async () => {
    if (!password) return;
    try {
      await navigator.clipboard.writeText(password);
      // Provide feedback by temporarily changing the copy button text
      alert('Password copied to clipboard');
    } catch (err) {
      alert('Failed to copy: ' + err.message);
    }
  };

  // Determine whether generation button should be enabled
  const canGenerate = entropy && !loading;

  return (
    <div className="container">
      <div className="header">
        <img src="logo.png" alt="rdmpass logo" />
        <div>
          <div className="title">rdmpass</div>
          <div className="subtitle">True random password generator</div>
        </div>
      </div>
      <div className="section">
        <h2>1. Collect randomness</h2>
        {!entropy ? (
          <div>
            <p>
              Move your mouse around the window to generate entropy. The
              randomness used to create your password is derived entirely
              from your unique movement pattern. The more you move, the
              stronger the key.
            </p>
            <div className="controls">
              <div className="control-group">
                <label htmlFor="requiredMoves">Number of mouse movements</label>
                <input
                  id="requiredMoves"
                  type="range"
                  min="50"
                  max="1000"
                  step="10"
                  value={requiredMoves}
                  onChange={(e) => setRequiredMoves(parseInt(e.target.value))}
                />
                <div>{requiredMoves}</div>
              </div>
              <div className="control-group">
                <button onClick={startCollection} disabled={collecting}>
                  {collecting ? 'Collecting…' : 'Start collection'}
                </button>
              </div>
            </div>
            <div className="progress-bar-container">
              <div
                className="progress-bar"
                style={{ width: `${Math.round(progress * 100)}%` }}
              ></div>
            </div>
            <div style={{ marginTop: '0.5rem', fontSize: '0.8rem' }}>
              {Math.min(mouseCount, requiredMoves)} / {requiredMoves} moves
              collected
            </div>
          </div>
        ) : (
          <div>
            <p>
              Entropy collected. You can now customize your password and
              generate it.
            </p>
            <button onClick={startCollection}>Re‑collect entropy</button>
          </div>
        )}
      </div>
      <div className="section">
        <h2>2. Configure password</h2>
        <div className="controls">
          <div className="control-group">
            <label htmlFor="passwordLength">Password length</label>
            <input
              id="passwordLength"
              type="range"
              min="4"
              max="128"
              step="1"
              value={passwordLength}
              onChange={(e) => setPasswordLength(parseInt(e.target.value))}
            />
            <div>{passwordLength}</div>
          </div>
          <div className="control-group">
            <label>
              <input
                type="checkbox"
                checked={includeLowercase}
                onChange={(e) => setIncludeLowercase(e.target.checked)}
              />
              Lowercase (a‑z)
            </label>
            <label>
              <input
                type="checkbox"
                checked={includeUppercase}
                onChange={(e) => setIncludeUppercase(e.target.checked)}
              />
              Uppercase (A‑Z)
            </label>
            <label>
              <input
                type="checkbox"
                checked={includeNumbers}
                onChange={(e) => setIncludeNumbers(e.target.checked)}
              />
              Numbers (0‑9)
            </label>
            <label>
              <input
                type="checkbox"
                checked={includeSymbols}
                onChange={(e) => setIncludeSymbols(e.target.checked)}
              />
              Symbols (!@#$…)
            </label>
            <label>
              <input
                type="checkbox"
                checked={includeExtendedLatin}
                onChange={(e) => setIncludeExtendedLatin(e.target.checked)}
              />
              Extended Latin
            </label>
            <label>
              <input
                type="checkbox"
                checked={requireEachSelected}
                onChange={(e) => setRequireEachSelected(e.target.checked)}
              />
              Require one of each selected
            </label>
          </div>
          <div className="control-group">
            <label htmlFor="customChars">Custom characters</label>
            <input
              id="customChars"
              type="text"
              placeholder="Add your own characters"
              value={customCharacters}
              onChange={(e) => setCustomCharacters(e.target.value)}
            />
          </div>
        </div>
      </div>
      <div className="section">
        <h2>3. Generate password</h2>
        <div className="button-row">
          <button onClick={generatePassword} disabled={!canGenerate}>
            {loading ? 'Generating…' : 'Generate Password'}
          </button>
          <button onClick={resetAll} disabled={loading}>
            Reset
          </button>
        </div>
        {error && <div style={{ color: 'red', marginTop: '0.5rem' }}>{error}</div>}
        {password && (
          <div className="password-display">
            {password}
            <button className="copy-button" onClick={copyPassword} title="Copy to clipboard">
              copy
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);