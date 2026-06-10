/**
 * ============================================================================
 * Politechnika Śląska
 * Wydział Inżynierii Materiałowej i Cyfryzacji Przemysłu
 * Kierunek: Informatyka Przemysłowa
 * * PROJEKT INŻYNIERSKI
 * Tytuł: "Kryptograficznie weryfikowalny dziennik audytu operacji w systemach webowych"
 * * Autor: Kamil Żurek
 * Nr albumu: 305428
 * Prowadzący pracę: dr inż. Łukasz Maliński
 * Rok akademicki: 2025/2026
 * ============================================================================
 */


import { useState, useEffect, useCallback, useMemo } from 'react';
import './App.css';

const sha256 = async (message) => {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

const parseJwt = (token) => {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map(c =>
        '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
    ).join(''));

    const payload = JSON.parse(jsonPayload);
    const roleKey = Object.keys(payload).find(k => k.includes('role'));
    const nameKey = Object.keys(payload).find(k => k.includes('name'));

    return {
      role: payload[roleKey] || 'User',
      username: payload[nameKey] || 'Użytkownik'
    };
  } catch {
    return null;
  }
};

function App() {
  const [token, setToken] = useState(localStorage.getItem('token') || '');
  const [view, setView] = useState('login');

  const [adminTab, setAdminTab] = useState('logs'); // 'logs', 'operations' lub 'server'
  const [serverStatus, setServerStatus] = useState(null);

  const [authData, setAuthData] = useState({ username: '', password: '', firstName: '', lastName: '', email: '', role: 'User' });
  const [transferData, setTransferData] = useState({ receiver: '', amount: '' });

  const [logs, setLogs] = useState([]);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  // --- STAN MODALI (OKIENEK) ---
  const [modalConfig, setModalConfig] = useState({
    isOpen: false,
    type: 'info',
    title: '',
    message: '',
    onConfirm: null
  });

  const showModal = (title, msg, type = 'info') => {
    setModalConfig({ isOpen: true, type, title, message: msg, onConfirm: null });
  };

  const showConfirm = (title, msg, onConfirmCallback) => {
    setModalConfig({ isOpen: true, type: 'confirm', title, message: msg, onConfirm: onConfirmCallback });
  };

  const closeModal = () => {
    setModalConfig({ ...modalConfig, isOpen: false });
  };
  // ------------------------------------

  const user = useMemo(() => token ? parseJwt(token) : null, [token]);

  const handleLogout = useCallback((alertMessage = null, isError = false) => {
    if (alertMessage) {
      showModal(isError ? "Błąd Autoryzacji" : "Informacja", alertMessage, isError ? "error" : "info");
    }
    setToken('');
    localStorage.removeItem('token');
    setLogs([]);
    setMessage('');
    setError('');
  }, []);

  const fetchLogs = useCallback(async () => {
    if (!token) return;
    try {
      const res = await fetch('https://localhost:7274/api/Audit', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setLogs(data);
      } else if (res.status === 401 || res.status === 403) {
        handleLogout("Twoja sesja wygasła lub baza danych została zresetowana. Zaloguj się ponownie.", true);
      }
    } catch (err) {
      console.error("Błąd pobierania danych", err);
    }
  }, [token, handleLogout]);

  useEffect(() => {
    let isMounted = true;

    const loadData = async () => {
      if (token && isMounted) {
        await fetchLogs();
      }
    };

    loadData().catch(console.error);

    return () => {
      isMounted = false;
    };
  }, [token, fetchLogs]);

  const handleVerify = async (logId, targetHash) => {
    try {
      const proofRes = await fetch(`https://localhost:7274/api/Audit/proof/${logId}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (proofRes.status === 401) {
        handleLogout("Twoja sesja wygasła!", true);
        return;
      }

      if (!proofRes.ok) {
        const errorText = await proofRes.text();
        throw new Error(errorText);
      }

      const proofData = await proofRes.json();
      const rootRes = await fetch(`https://localhost:7274/api/Audit/root`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!rootRes.ok) throw new Error("Nie udało się pobrać Głównego Korzenia Drzewa!");

      const rootData = await rootRes.json();
      const serverRoot = rootData.currentRoot;
      const proof = proofData.proof;

      let computedHash = targetHash;
      for (let i = 0; i < proof.length; i++) {
        const sibling = proof[i];
        let combined = sibling.direction === "Left" ? sibling.hash + computedHash : computedHash + sibling.hash;
        computedHash = await sha256(combined);
      }

      if (computedHash === serverRoot) {
        showModal(
            "✅ WERYFIKACJA POZYTYWNA",
            `Przelew ID: ${logId} został kryptograficznie zweryfikowany.\nZgromadzone dowody wyliczyły Hash:\n${computedHash}\n\nPokrywa się on idealnie z głównym korzeniem na serwerze!`,
            "success"
        );
      } else {
        showModal(
            "🚨 DANE ZMANIPULOWANE!",
            `Drzewo zostało uszkodzone.\nWyliczony Hash:\n${computedHash}\nOczekiwany (Serwer):\n${serverRoot}`,
            "error"
        );
      }

    } catch (err) {
      showModal("Blokada Weryfikacji", err.message, "error");
    }
  };

  const fetchServerStatus = async () => {
    try {
      const res = await fetch('https://localhost:7274/api/Audit/status', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setServerStatus(data);
      }
    } catch (error) {
      console.error("Błąd pobierania statusu serwera", error);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch('https://localhost:7274/api/Auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(authData)
      });
      if (res.ok) {
        setMessage('Konto utworzone! Możesz się teraz zalogować.');
        setView('login');
      } else setError('Błąd rejestracji. Sprawdź dane lub nazwa jest zajęta.');
    } catch { setError('Błąd połączenia z serwerem.'); }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch('https://localhost:7274/api/Auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: authData.username, password: authData.password })
      });
      if (res.ok) {
        const data = await res.json();
        setToken(data.token);
        localStorage.setItem('token', data.token);
        setError('');
        setMessage('');
      } else setError('Błędny login lub hasło.');
    } catch { setError('Błąd połączenia z serwerem.'); }
  };

  const handleTransfer = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch('https://localhost:7274/api/Audit/transfer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ receiver: transferData.receiver, amount: parseFloat(transferData.amount) })
      });

      if (res.status === 401) {
        handleLogout("Sesja wygasła! Operacja odrzucona.", true);
        return;
      }

      if (res.ok) {
        setMessage('Przelew zrealizowany! (Ślad IP został zapisany).');
        setTransferData({ receiver: '', amount: '' });
        await fetchLogs();
      } else {
        const errData = await res.json();
        setError(errData.message || 'Błąd podczas wykonywania przelewu.');
      }
    } catch { setError('Błąd połączenia z serwerem.'); }
  };

  const handleSimulateAttack = () => {
    showConfirm(
        "⚠️ SYMULACJA ATAKU",
        "UWAGA! To uszkodzi integralność bazy danych. Zmienimy kwotę ostatniego przelewu omijając zabezpieczenia kryptograficzne.\n\nCzy na pewno chcesz kontynuować?",
        async () => {
          try {
            const targetId = logs.length > 0 ? logs[0].id : 1;
            const res = await fetch(`https://localhost:7274/api/Audit/simulate-attack/${targetId}?recalculateHash=false`, {
              method: 'POST',
              headers: { 'Authorization': `Bearer ${token}` }
            });

            if (res.status === 401) {
              handleLogout("Zbyt słabe uprawnienia lub sesja wygasła!", true);
              return;
            }

            if (res.ok) {
              showModal("🚨 BAZA ZAINFEKOWANA!", "Zmodyfikowano przelew z pominięciem procedur kryptograficznych. Watchdog wykryje zmianę w kolejnym cyklu.", "error");
              await fetchLogs();
            }
          } catch (err) { console.error("Błąd ataku", err); }
        }
    );
  };

  const handleRevertAttack = async () => {
    try {
      const targetId = logs.length > 0 ? logs[0].id : 1;
      const res = await fetch(`https://localhost:7274/api/Audit/revert-attack/${targetId}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (res.ok) {
        showModal("✅ BAZA NAPRAWIONA", "Cofnięto modyfikacje hakera. Kryptograficzna spójność bazy została przywrócona. API odblokowane.", "success");
        await fetchLogs();
        await fetchServerStatus();
      } else {
        showModal("Błąd", "Nie udało się naprawić bazy danych.", "error");
      }
    } catch (err) {
      console.error("Błąd naprawy bazy", err);
    }
  };

  const handleResetQuarantine = async () => {
    try {
      const res = await fetch('https://localhost:7274/api/Audit/reset-quarantine', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (res.ok) {
        showModal("✅ KWARANTANNA ZDJĘTA na siłę", "System zabezpieczeń został zresetowany, ale jeśli baza wciąż jest uszkodzona, Watchdog włączy kwarantannę ponownie.", "success");
        await fetchServerStatus();
      } else {
        showModal("Błąd", "Nie udało się zdjąć kwarantanny.", "error");
      }
    } catch (err) {
      console.error("Błąd resetowania kwarantanny", err);
    }
  };

  const handleResetDatabase = async () => {
    showConfirm(
        "⚠️ CZYSZCZENIE BAZY DANYCH",
        "Czy na pewno chcesz usunąć WSZYSTKIE przelewy? Tej operacji nie można cofnąć! System zostanie zresetowany do stanu fabrycznego.",
        async () => {
          try {
            const res = await fetch('https://localhost:7274/api/Audit/reset-database', {
              method: 'DELETE',
              headers: { 'Authorization': `Bearer ${token}` }
            });

            if (res.ok) {
              showModal("🧹 BAZA WYCZYSZCZONA", "Wszystkie rekordy usunięte. Licznik ID zresetowany. System gotowy do nowej prezentacji.", "success");
              await fetchLogs();
              await fetchServerStatus();
            } else {
              showModal("Błąd", "Nie udało się wyczyścić bazy.", "error");
            }
          } catch (err) { console.error("Błąd resetowania bazy", err); }
        }
    );
  };

  // --- BEZPIECZNE GENEROWANIE DANYCH (Przez oficjalne API) ---
  const handleSeedDatabase = async () => {
    const receivers = ["Jan Kowalski", "Sklep Elektroniczny", "Anna Nowak", "Księgarnia Naukowa", "Politechnika Śląska", "Urząd Skarbowy", "Hurtownia IT"];

    showConfirm(
        "🎲 GENEROWANIE DANYCH",
        "Za chwilę system zasymuluje 10 poprawnych przelewów, wysyłając je przez oficjalne API transferowe.\nZbuduje to poprawny łańcuch bez alarmowania Watchdoga.\n\nKontynuować?",
        async () => {
          try {
            // Wykonujemy 10 strzałów do natywnego, SPRAWDZONEGO endpointu transferu!
            for(let i = 0; i < 10; i++) {
              const receiver = receivers[Math.floor(Math.random() * receivers.length)];
              const amount = Math.floor(Math.random() * 2500) + 50; // Pełne kwoty, aby uniknąć ucinania zer w SQLite

              const res = await fetch('https://localhost:7274/api/Audit/transfer', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ receiver: receiver, amount: amount })
              });

              if (!res.ok) throw new Error("Odrzucono przelew nr " + (i+1));
            }

            showModal("✅ DANE WYGENEROWANE", "Pomyślnie zasilono bazę przez bezpieczne API. Drzewo Merkle zaktualizowało się naturalnie.", "success");
            await fetchLogs(); // Odświeżenie tabeli
          } catch (err) {
            console.error("Błąd seedowania", err);
            showModal("Błąd", "Generowanie przerwane: " + err.message, "error");
          }
        }
    );
  };

  const renderModal = () => {
    if (!modalConfig.isOpen) return null;
    return (
        <div className="modal-overlay">
          <div className={`modal-box modal-${modalConfig.type}`}>
            <div className="modal-header">
              <h3>{modalConfig.title}</h3>
            </div>
            <div className="modal-body">
              {modalConfig.message.split('\n').map((line, idx) => (
                  <span key={idx}>{line}<br/></span>
              ))}
            </div>
            <div className="modal-actions">
              {modalConfig.type === 'confirm' ? (
                  <>
                    <button className="btn btn-secondary" onClick={closeModal}>Anuluj</button>
                    <button className="btn btn-danger" onClick={() => { modalConfig.onConfirm(); closeModal(); }}>
                      🔥 Kontynuuj
                    </button>
                  </>
              ) : (
                  <button className={`btn btn-${modalConfig.type === 'error' ? 'danger' : 'primary'}`} onClick={closeModal}>
                    Zrozumiałem
                  </button>
              )}
            </div>
          </div>
        </div>
    );
  };

  if (!token) {
    return (
        <>
          {renderModal()}
          <div className="login-wrapper">
            <div className="auth-card">
              <h2>{view === 'login' ? 'Panel Logowania' : 'Rejestracja'}</h2>

              {message && <div className="alert alert-success">{message}</div>}
              {error && <div className="alert alert-error">{error}</div>}

              <form onSubmit={view === 'login' ? handleLogin : handleRegister}>
                <div className="form-group">
                  <label>Nazwa użytkownika</label>
                  <input type="text" required value={authData.username} onChange={e => setAuthData({...authData, username: e.target.value})} />
                </div>

                {view === 'register' && (
                    <>
                      <div className="form-row">
                        <div className="form-group half">
                          <label>Imię</label>
                          <input type="text" required value={authData.firstName} onChange={e => setAuthData({...authData, firstName: e.target.value})} />
                        </div>
                        <div className="form-group half">
                          <label>Nazwisko</label>
                          <input type="text" required value={authData.lastName} onChange={e => setAuthData({...authData, lastName: e.target.value})} />
                        </div>
                      </div>
                      <div className="form-group">
                        <label>E-mail</label>
                        <input type="email" required value={authData.email} onChange={e => setAuthData({...authData, email: e.target.value})} />
                      </div>
                      <div className="form-group">
                        <label>Rola (demonstracja)</label>
                        <select value={authData.role} onChange={e => setAuthData({...authData, role: e.target.value})}>
                          <option value="User">Zwykły Użytkownik</option>
                          <option value="Admin">Administrator</option>
                        </select>
                      </div>
                    </>
                )}

                <div className="form-group">
                  <label>Hasło</label>
                  <input type="password" required value={authData.password} onChange={e => setAuthData({...authData, password: e.target.value})} />
                </div>

                <button type="submit" className="btn btn-primary">
                  {view === 'login' ? 'Zaloguj się' : 'Utwórz konto'}
                </button>
              </form>

              <div className="auth-footer">
                {view === 'login' ? (
                    <p>Nie masz konta? <button type="button" onClick={() => {setView('register'); setError(''); setMessage('');}} className="link-btn">Zarejestruj się</button></p>
                ) : (
                    <p>Masz już konto? <button type="button" onClick={() => {setView('login'); setError(''); setMessage('');}} className="link-btn">Zaloguj się</button></p>
                )}
              </div>
            </div>
          </div>
          <footer style={{
            textAlign: 'center',
            padding: '10px 15px 15px 15px',
            color: 'var(--text-muted)',
            fontSize: '13px',
            lineHeight: '1.9'
          }}>
            <strong style={{ color: '#e2e8f0' }}>Projekt Inżynierski</strong><br/>
            Kryptograficznie weryfikowalny dziennik audytu operacji w systemach webowych<br/>
            &copy; 2026 Kamil Żurek
          </footer>
        </>
    );
  }

  return (
      <>
        {renderModal()}
          <div className="dashboard-wrapper">
            <div className="dashboard-container">

              <header className="dashboard-header">
                <div>
                  <h1>System Audytu Transakcji</h1>
                  <p className="status-text">
                    Zalogowano jako: <span className="highlight">{user?.username}</span>
                    <span className={`badge ${user?.role === 'Admin' ? 'badge-admin' : 'badge-user'}`}>
                  {user?.role}
                </span>
                  </p>
                </div>
                <div className="header-actions">
                  {user?.role === 'Admin' && (
                      <button onClick={handleSimulateAttack} className="btn btn-danger pulse">
                        ⚠️ SYMULUJ ATAK
                      </button>
                  )}
                  <button onClick={() => handleLogout()} className="btn btn-secondary">
                    Wyloguj
                  </button>
                </div>
              </header>

              {message && <div className="alert alert-success">{message}</div>}
              {error && <div className="alert alert-error">{error}</div>}

              <div className="dashboard-grid">

                <div className="card new-transfer">
                  <h3>Nowy Przelew</h3>
                  <form onSubmit={handleTransfer}>
                    <div className="form-group">
                      <label>Odbiorca</label>
                      <input type="text" required value={transferData.receiver} onChange={e => setTransferData({...transferData, receiver: e.target.value})} placeholder="Nazwa odbiorcy" />
                    </div>
                    <div className="form-group">
                      <label>Kwota (PLN)</label>
                      <input type="number" step="0.01" required value={transferData.amount} onChange={e => setTransferData({...transferData, amount: e.target.value})} placeholder="0.00" />
                    </div>
                    <button type="submit" className="btn btn-success">
                      Zleć Przelew
                    </button>
                  </form>

                  {/* PRZYCISK DO GENEROWANIA DANYCH */}
                  {user?.role === 'Admin' && (
                      <>
                        <hr style={{ borderColor: 'var(--border-color)', margin: '20px 0' }} />
                        <button
                            type="button"
                            onClick={handleSeedDatabase}
                            className="btn btn-secondary"
                            style={{ width: '100%', fontSize: '13px' }}
                            title="Szybkie generowanie danych do prezentacji"
                        >
                          🎲 Wygeneruj 10 losowych wpisów
                        </button>
                      </>
                  )}
                </div>

                {user?.role === 'Admin' ? (
                    <div className="admin-dashboard-view" style={{ width: '100%' }}>
                      {/* NAWIGACJA ZAKŁADEK ADMINA */}
                      <div className="admin-tabs">
                        <button
                            className={`tab-btn ${adminTab === 'operations' ? 'active' : ''}`}
                            onClick={() => setAdminTab('operations')}
                        >
                          📊 Historia Operacji
                        </button>
                        <button
                            className={`tab-btn ${adminTab === 'logs' ? 'active' : ''}`}
                            onClick={() => setAdminTab('logs')}
                        >
                          📜 Dziennik Audytu
                        </button>
                        <button
                            className={`tab-btn ${adminTab === 'server' ? 'active' : ''}`}
                            onClick={() => { setAdminTab('server'); fetchServerStatus(); }}
                        >
                          🖥️ Status Serwera
                        </button>
                      </div>

                      {/* ZAKŁADKA 1: HISTORIA OPERACJI (Czysta tabela biznesowa) */}
                      {adminTab === 'operations' && (
                          <div className="card operations-table-card">
                            <div className="card-header">
                              <h3>Zestawienie Zrealizowanych Przelewów</h3>
                            </div>
                            <div className="table-responsive">
                              <table className="table">
                                <thead>
                                <tr>
                                  <th>ID</th>
                                  <th>Nadawca</th>
                                  <th>Odbiorca</th>
                                  <th className="text-right">Kwota</th>
                                  <th>Data operacji</th>
                                </tr>
                                </thead>
                                <tbody>
                                {logs.map((log) => (
                                    <tr key={log.id}>
                                      <td>{log.id}</td>
                                      <td className="font-medium">{log.sender}</td>
                                      <td>{log.receiver}</td>
                                      <td className="text-right text-blue" style={{ fontWeight: '600' }}>
                                        {log.amount.toFixed(2)} PLN
                                      </td>
                                      <td style={{ color: 'var(--text-muted)', fontSize: '14px' }}>
                                        {new Date(log.timestamp).toLocaleString('pl-PL')}
                                      </td>
                                    </tr>
                                ))}
                                </tbody>
                              </table>
                              {logs.length === 0 && <div className="empty-state">Brak operacji w systemie.</div>}
                            </div>
                          </div>
                      )}

                      {/* ZAKŁADKA 2: TABELA LOGÓW (Widok dla Administratora IT z IP i UserAgent) */}
                      {adminTab === 'logs' && (
                          <div className="card log-table-card">
                            <div className="card-header">
                              <h3>Rejestr Audytowy (Zabezpieczony Drzewem Merkle)</h3>
                            </div>
                            <div className="table-responsive">
                              <table>
                                <thead>
                                <tr>
                                  <th>Nadawca</th>
                                  <th>Odbiorca</th>
                                  <th className="text-right">Kwota</th>
                                  <th>Adres IP</th>
                                  <th>Ślad (User-Agent)</th>
                                  <th>Kryptograficzny Hash</th>
                                  <th className="text-center">Akcja</th>
                                </tr>
                                </thead>
                                <tbody>
                                {logs.map((log) => (
                                    <tr key={log.id}>
                                      <td className="font-medium">{log.sender}</td>
                                      <td>{log.receiver}</td>
                                      <td className="text-right text-blue" style={{ whiteSpace: 'nowrap' }}>
                                        {log.amount.toFixed(2)} PLN
                                      </td>
                                      <td>
                                      <span style={{ backgroundColor: 'rgba(255,255,255,0.1)', border: '1px solid var(--border-color)', color: '#cbd5e1', fontSize: '11px', padding: '3px 6px', borderRadius: '4px', fontFamily: 'monospace' }}>
                                        {log.ipAddress || '127.0.0.1'}
                                      </span>
                                      </td>
                                      <td
                                          style={{ maxWidth: '120px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontSize: '12px', color: 'var(--text-muted)' }}
                                          title={log.userAgent}
                                      >
                                        {log.userAgent || 'Nieznane urządzenie'}
                                      </td>
                                      <td className="hash-col" title={log.hash} style={{ maxWidth: '100px' }}>
                                        {log.hash}
                                      </td>
                                      <td className="text-center">
                                        <button
                                            onClick={() => handleVerify(log.id, log.hash)}
                                            className="btn btn-secondary"
                                            style={{ padding: '6px 12px', fontSize: '12px' }}
                                        >
                                          🔍 Weryfikuj
                                        </button>
                                      </td>
                                    </tr>
                                ))}
                                </tbody>
                              </table>
                              {logs.length === 0 && <div className="empty-state">Brak logów w systemie.</div>}
                            </div>
                          </div>
                      )}

                      {/* ZAKŁADKA 3: STATUS SERWERA */}
                      {adminTab === 'server' && (
                          <div className="card server-status-card">
                            <div className="card-header">
                              <h3>Monitorowanie Systemu (Watchdog)</h3>
                              <button className="btn btn-primary" onClick={fetchServerStatus} style={{ padding: '6px 12px', fontSize: '13px' }}>
                                🔄 Odśwież Status
                              </button>
                            </div>
                            <div className="card-body">
                              {serverStatus ? (
                                  <div className="status-container">
                                    <div className={`status-banner ${serverStatus.isQuarantineActive ? 'quarantine' : 'safe'}`}>
                                      {serverStatus.isQuarantineActive ? (
                                          <>
                                            <span className="icon-huge">🚨</span>
                                            <h2>SYSTEM ZABLOKOWANY (KWARANTANNA)</h2>
                                            <p className="reason-text">{serverStatus.quarantineReason}</p>
                                            <p className="action-text" style={{ marginTop: '10px' }}>
                                              Interfejs API odrzuci wszelkie próby wykonania nowych przelewów.
                                            </p>

                                            {/* ZESTAW PRZYCISKÓW RATUNKOWYCH */}
                                            <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', marginTop: '20px' }}>
                                              <button
                                                  onClick={handleResetQuarantine}
                                                  className="btn btn-secondary"
                                                  style={{ padding: '10px 15px', fontWeight: 'bold' }}
                                              >
                                                🔓 Zdejmij blokadę na siłę (niezalecane)
                                              </button>
                                              <button
                                                  onClick={handleRevertAttack}
                                                  className="btn btn-success"
                                                  style={{ padding: '10px 15px', fontWeight: 'bold' }}
                                              >
                                                🛠️ Napraw bazę i przywróć spójność
                                              </button>
                                            </div>
                                          </>
                                      ) : (
                                          <>
                                            <span className="icon-huge">🛡️</span>
                                            <h2>SYSTEM BEZPIECZNY</h2>
                                            <p>Brak wykrytych modyfikacji. Zgodność kryptograficzna drzewa Merkle potwierdzona.</p>
                                          </>
                                      )}
                                    </div>

                                    <div className="status-details" style={{ marginTop: '20px' }}>
                                      <div className="detail-item">
                                        <strong>Stan usługi Watchdog:</strong>
                                        <span className="badge-active">{serverStatus.watchdogStatus}</span>
                                      </div>
                                      <div className="detail-item">
                                        <strong>Czas serwera (UTC):</strong>
                                        <span>{serverStatus.serverTime}</span>
                                      </div>
                                    </div>

                                    {/* NOWY PRZYCISK RESETU BAZY */}
                                    <hr style={{ borderColor: 'var(--border-color)', margin: '20px 0' }} />
                                    <div style={{ textAlign: 'center' }}>
                                      <button
                                          onClick={handleResetDatabase}
                                          className="btn btn-danger"
                                          style={{ padding: '10px 20px', fontWeight: 'bold' }}
                                      >
                                        🗑️ Wyczyść całą bazę (Hard Reset)
                                      </button>
                                    </div>

                                  </div>
                              ) : (
                                  <div className="empty-state">Pobieranie statusu z serwera...</div>
                              )}
                            </div>
                          </div>
                      )}
                    </div>
                ) : (
                    /* WIDOK DLA ZWYKŁEGO UŻYTKOWNIKA - CZYSTA HISTORIA PRZELEWÓW Z PRZYCISKIEM WERYFIKACJI */
                    <div className="card user-history-card" style={{ width: '100%' }}>
                      <div className="card-header">
                        <h3>Historia Twoich Przelewów</h3>
                      </div>
                      <div className="table-responsive">
                        <table className="table">
                          <thead>
                          <tr>
                            <th>Odbiorca</th>
                            <th className="text-right">Kwota</th>
                            <th>Data operacji</th>
                            <th className="text-center">Bezpieczeństwo (Zero-Trust)</th>
                          </tr>
                          </thead>
                          <tbody>
                          {logs.map((log) => (
                              <tr key={log.id}>
                                <td className="font-medium">{log.receiver}</td>
                                <td className="text-right text-blue" style={{ fontWeight: '600' }}>
                                  - {log.amount.toFixed(2)} PLN
                                </td>
                                <td style={{ color: 'var(--text-muted)', fontSize: '14px' }}>
                                  {new Date(log.timestamp).toLocaleString('pl-PL')}
                                </td>
                                <td className="text-center" style={{ display: 'flex', gap: '10px', justifyContent: 'center', alignItems: 'center' }}>
                                <span className="badge-user" style={{ backgroundColor: 'rgba(22, 163, 74, 0.15)', color: '#4ade80', padding: '4px 12px', borderRadius: '12px', fontSize: '12px', fontWeight: 'bold' }}>
                                  🛡️ Zapisano
                                </span>
                                  <button
                                      onClick={() => handleVerify(log.id, log.hash)}
                                      className="btn btn-secondary"
                                      style={{ padding: '4px 10px', fontSize: '12px', backgroundColor: 'transparent', border: '1px solid var(--border-color)' }}
                                      title="Pobierz dowód Merkle i zweryfikuj matematycznie"
                                  >
                                    🔍 Weryfikuj
                                  </button>
                                </td>
                              </tr>
                          ))}
                          </tbody>
                        </table>
                        {logs.length === 0 && (
                            <div className="empty-state" style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
                              Nie wykonałeś jeszcze żadnych przelewów.
                            </div>
                        )}
                      </div>
                    </div>
                )}
              </div>
              <footer style={{
                textAlign: 'center',
                padding: '25px 15px 15px 15px',
                marginTop: '40px',
                borderTop: '1px solid var(--border-color)',
                color: 'var(--text-muted)',
                fontSize: '13px',
                lineHeight: '1.6'
              }}>
                <strong style={{ color: '#e2e8f0' }}>Projekt Inżynierski</strong><br/>
                Kryptograficznie weryfikowalny dziennik audytu operacji w systemach webowych<br/>
                &copy; 2026 Kamil Żurek
              </footer>

            </div>
          </div>
      </>
  );
}

export default App;