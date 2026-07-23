import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useNavigate, Navigate } from 'react-router-dom';
import axios from 'axios';
import { Shield, FileText, LayoutDashboard, CheckCircle, Upload, AlertCircle, LogIn, LogOut, Star, Car, Mail } from 'lucide-react';

const API_BASE_URL = '/api';

// Send the httpOnly session cookie on every request.
axios.defaults.withCredentials = true;

// --- Components ---

const Navbar = ({ isAdmin, onLogout }: { isAdmin: boolean; onLogout: () => void }) => (
  <nav className="bg-green-700 text-white p-4 shadow-lg mb-8">
    <div className="container mx-auto flex justify-between items-center">
      <Link to="/" className="text-2xl font-bold flex items-center gap-2">
        <Star size={32} className="text-yellow-400 fill-yellow-400" />
        <span>STAR ASSURANCES</span>
      </Link>
      <div className="flex gap-6 items-center">
        <Link to="/" className="hover:text-green-200 transition font-medium">Déclarer un Sinistre</Link>
        {isAdmin ? (
          <>
            <Link to="/admin" className="hover:text-green-200 transition flex items-center gap-1 font-medium">
              <LayoutDashboard size={18} />
              Tableau de bord
            </Link>
            <button onClick={onLogout} className="flex items-center gap-1 bg-red-600 px-3 py-1 rounded hover:bg-red-700 transition font-medium">
              <LogOut size={18} />
              Déconnexion
            </button>
          </>
        ) : (
          <Link to="/login" className="hover:text-green-200 transition flex items-center gap-1 font-medium">
            <LogIn size={18} />
            Espace Agent
          </Link>
        )}
      </div>
    </div>
  </nav>
);

const Login = ({ onLogin }: { onLogin: () => void }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      // Real backend check. The server sets an httpOnly session cookie on
      // success - the frontend never sees or stores the token itself.
      await axios.post(`${API_BASE_URL}/login`, { username, password });
      onLogin();
      navigate('/admin');
    } catch (error) {
      alert('Identifiants invalides');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="max-w-md mx-auto bg-white p-8 rounded-xl shadow-xl mt-20 border-t-4 border-green-700">
      <div className="flex justify-center mb-6">
        <Star size={48} className="text-green-700 fill-green-700" />
      </div>
      <h2 className="text-2xl font-bold text-gray-800 mb-6 text-center">
        Connexion Agent STAR
      </h2>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700">Nom d'utilisateur</label>
          <input type="text" required value={username} onChange={e => setUsername(e.target.value)} className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-green-500 focus:ring-green-500 p-2 border" />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Mot de passe</label>
          <input type="password" required value={password} onChange={e => setPassword(e.target.value)} className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-green-500 focus:ring-green-500 p-2 border" />
        </div>
        <button type="submit" disabled={submitting} className="w-full bg-green-700 text-white py-3 rounded-lg font-bold hover:bg-green-800 transition shadow-md disabled:opacity-60">
          {submitting ? 'Connexion...' : 'Se connecter'}
        </button>
      </form>
    </div>
  );
};

// Files the app will accept. This is a UX convenience only - the backend
// independently re-validates extension, content-type, AND magic bytes on
// every upload, since anything client-side is trivially spoofable.
const ALLOWED_MIME_TYPES = ['application/pdf', 'image/jpeg', 'image/png'];
const ALLOWED_EXTENSIONS = ['.pdf', '.jpg', '.jpeg', '.png'];

const DeclarationForm = () => {
  const [carData, setCarData] = useState<Record<string, string[]>>({});
  const [makes, setMakes] = useState<string[]>([]);
  const [selectedMake, setSelectedMake] = useState('');
  const [selectedModel, setSelectedModel] = useState('');
  const [immatriculation, setImmatriculation] = useState('');

  const [formData, setFormData] = useState({
    full_name: '',
    email: '',
    cin: '',
    policy_number: '',
    phone_number: '+216'
  });
  const [files, setFiles] = useState<File[]>([]);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    axios.get(`${API_BASE_URL}/car-models`)
      .then(res => {
        setCarData(res.data);
        setMakes(Object.keys(res.data));
      })
      .catch(err => console.error("Error fetching car models", err));
  }, []);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files) return;

    const selected = Array.from(e.target.files);
    const valid: File[] = [];
    const rejected: string[] = [];

    selected.forEach(file => {
      const ext = file.name.slice(file.name.lastIndexOf('.')).toLowerCase();
      const typeOk = ALLOWED_MIME_TYPES.includes(file.type);
      const extOk = ALLOWED_EXTENSIONS.includes(ext);

      if (typeOk && extOk) {
        valid.push(file);
      } else {
        rejected.push(file.name);
      }
    });

    if (rejected.length > 0) {
      alert(`Fichier(s) refusé(s) (formats acceptés: PDF, JPG, PNG) : ${rejected.join(', ')}`);
    }

    setFiles(valid);
  };

  const validateTunisianData = () => {
    const cinRegex = /^[0-9]{8}$/;
    const phoneRegex = /^\+216[0-9]{8}$/;
    const plateTNRegex = /^[0-9]{1,3}\s?TN\s?[0-9]{1,4}$/i;
    const plateRSRegex = /^RS\s?[0-9]{1,6}$/i;

    if (!cinRegex.test(formData.cin)) {
      alert('Le CIN doit contenir exactement 8 chiffres.');
      return false;
    }
    if (!phoneRegex.test(formData.phone_number)) {
      alert('Le numéro de téléphone doit être au format +216 suivi de 8 chiffres.');
      return false;
    }
    if (!selectedMake || !selectedModel) {
      alert('Veuillez sélectionner la marque et le modèle du véhicule.');
      return false;
    }
    if (!plateTNRegex.test(immatriculation) && !plateRSRegex.test(immatriculation)) {
      alert('Format d\'immatriculation invalide. Exemples valides: "123 TN 4567" ou "RS 123456".');
      return false;
    }
    if (files.length === 0) {
      alert('Veuillez télécharger au moins un document (constat ou photo).');
      return false;
    }
    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateTunisianData()) return;

    setLoading(true);
    const data = new FormData();
    Object.entries(formData).forEach(([key, value]) => {
      if (value) data.append(key, value);
    });
    data.append('vehicle_details', `Véhicule: ${selectedMake} ${selectedModel} | Immatriculation: ${immatriculation.toUpperCase()}`);
    files.forEach(file => data.append('files', file));

    try {
      await axios.post(`${API_BASE_URL}/claims`, data);
      setSuccess(true);
    } catch (error: any) {
      console.error('Submission failed', error);
      const detail = error?.response?.data?.detail;
      alert(detail ? `Erreur: ${detail}` : 'Erreur lors de la soumission. Veuillez réessayer.');
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <div className="max-w-2xl mx-auto bg-white p-12 rounded-xl shadow-2xl text-center mt-10 border-t-8 border-green-500">
        <CheckCircle size={80} className="mx-auto text-green-500 mb-6" />
        <h2 className="text-3xl font-bold text-gray-800 mb-4">Déclaration Envoyée !</h2>
        <p className="text-gray-600 mb-8 text-lg">Votre déclaration d'accident a été reçue par STAR Assurances. Un agent traitera votre dossier dans les plus brefs délais.</p>
        <button onClick={() => window.location.reload()} className="bg-green-700 text-white px-8 py-3 rounded-lg font-semibold hover:bg-green-800 transition shadow-lg">
          Retour à l'accueil
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto bg-white rounded-xl shadow-2xl overflow-hidden mb-12 mt-4 border border-gray-100">
      <div className="bg-green-700 text-white p-8 flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold">Déclaration de Sinistre</h2>
          <p className="opacity-90 mt-2 text-lg">Formulaire digital de STAR Assurances - Tunisie</p>
        </div>
        <Star size={72} className="text-yellow-400 opacity-30 hidden md:block" />
      </div>
      <form onSubmit={handleSubmit} className="p-8 grid grid-cols-1 md:grid-cols-2 gap-8">
        <div className="space-y-6">
          <h3 className="text-xl font-bold border-b-2 border-green-700 pb-2 flex items-center gap-2 text-green-800">
            <FileText size={22} />
            Informations Personnelles
          </h3>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-semibold text-gray-700">Nom Complet</label>
              <input required name="full_name" onChange={handleInputChange} className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-green-500 focus:ring-green-500 p-2.5 border" />
            </div>
            <div>
              <label className="block text-sm font-semibold text-gray-700 flex items-center gap-1">
                E-mail <span className="text-gray-400 font-normal">(Optionnel)</span>
                <Mail size={14} className="text-gray-400" />
              </label>
              <input type="email" name="email" onChange={handleInputChange} placeholder="exemple@email.com" className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-green-500 focus:ring-green-500 p-2.5 border" />
              <p className="text-xs text-gray-500 mt-1 italic">Recevez des notifications automatiques sur l'état de votre dossier.</p>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-semibold text-gray-700">CIN (8 chiffres)</label>
                <input required name="cin" maxLength={8} onChange={handleInputChange} className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-green-500 focus:ring-green-500 p-2.5 border" placeholder="12345678" />
              </div>
              <div>
                <label className="block text-sm font-semibold text-gray-700">N° de Police</label>
                <input required name="policy_number" onChange={handleInputChange} className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-green-500 focus:ring-green-500 p-2.5 border" />
              </div>
            </div>
            <div>
              <label className="block text-sm font-semibold text-gray-700">Téléphone (Format: +216XXXXXXXX)</label>
              <input required name="phone_number" value={formData.phone_number} onChange={handleInputChange} className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-green-500 focus:ring-green-500 p-2.5 border" />
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <h3 className="text-xl font-bold border-b-2 border-green-700 pb-2 flex items-center gap-2 text-green-800">
            <Car size={22} />
            Détails Véhicule
          </h3>
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-semibold text-gray-700">Marque</label>
                <select
                  required
                  value={selectedMake}
                  onChange={(e) => { setSelectedMake(e.target.value); setSelectedModel(''); }}
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-green-500 focus:ring-green-500 p-2.5 border bg-white"
                >
                  <option value="">Choisir...</option>
                  {makes.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-sm font-semibold text-gray-700">Modèle</label>
                <select
                  required
                  disabled={!selectedMake}
                  value={selectedModel}
                  onChange={(e) => setSelectedModel(e.target.value)}
                  className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-green-500 focus:ring-green-500 p-2.5 border bg-white disabled:bg-gray-100"
                >
                  <option value="">Choisir...</option>
                  {selectedMake && carData[selectedMake].map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              </div>
            </div>
            <div>
              <label className="block text-sm font-semibold text-gray-700">Immatriculation (ex: 123 TN 4567 ou RS 123456)</label>
              <input
                required
                placeholder="123 TN 4567"
                value={immatriculation}
                onChange={(e) => setImmatriculation(e.target.value)}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-green-500 focus:ring-green-500 p-2.5 border uppercase"
              />
            </div>
            <div className="bg-yellow-50 p-4 rounded-lg border border-yellow-100">
               <p className="text-sm text-yellow-800 flex items-start gap-2">
                 <AlertCircle size={20} className="shrink-0" />
                 Assurez-vous de joindre le constat d'accident dûment rempli et signé dans la section ci-dessous.
               </p>
            </div>
          </div>
        </div>

        <div className="md:col-span-2 space-y-4">
          <h3 className="text-xl font-bold border-b-2 border-green-700 pb-2 flex items-center gap-2 text-green-800">
            <Upload size={22} />
            Pièces Jointes (Constat d'accident, Photos)
          </h3>
          <div className="border-2 border-dashed border-green-300 rounded-lg p-10 text-center hover:border-green-500 transition cursor-pointer relative bg-green-50/30">
            <input type="file" multiple accept=".pdf,.png,.jpg,.jpeg" onChange={handleFileChange} className="absolute inset-0 w-full h-full opacity-0 cursor-pointer" />
            <Upload size={48} className="mx-auto text-green-600 mb-3" />
            <p className="text-gray-700 font-semibold text-lg">Cliquez ou glissez les fichiers ici</p>
            <p className="text-gray-500 mt-1">Formats acceptés : PDF, PNG, JPG</p>
            {files.length > 0 && (
              <div className="mt-6 text-green-800 font-bold bg-green-200 py-3 px-6 rounded-full inline-block shadow-sm">
                {files.length} fichier(s) sélectionné(s)
              </div>
            )}
          </div>
        </div>

        <div className="md:col-span-2 pt-4">
          <button type="submit" disabled={loading} className={`w-full py-4 rounded-xl text-white font-bold text-xl transition shadow-xl ${loading ? 'bg-gray-400' : 'bg-green-700 hover:bg-green-800 hover:scale-[1.01] transform'}`}>
            {loading ? 'Envoi en cours...' : 'Envoyer la Déclaration à STAR'}
          </button>
        </div>
      </form>
    </div>
  );
};

const AdminDashboard = ({ isAdmin }: { isAdmin: boolean | null }) => {
  const [claims, setClaims] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (isAdmin) fetchClaims();
  }, [isAdmin]);

  const fetchClaims = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/claims`);
      setClaims(response.data);
    } catch (error) {
      console.error('Failed to fetch claims', error);
    } finally {
      setLoading(false);
    }
  };

  const updateStatus = async (id: number, status: string) => {
    try {
      await axios.patch(`${API_BASE_URL}/claims/${id}/status?status=${status}`);
      fetchClaims();
    } catch (error) {
      alert('Erreur lors de la mise à jour');
    }
  };

  // isAdmin is null while the /me check is still in flight - don't redirect
  // prematurely, or a real logged-in agent gets bounced on every refresh.
  if (isAdmin === null) {
    return (
      <div className="flex justify-center p-20">
        <div className="animate-spin rounded-full h-16 w-16 border-t-4 border-b-4 border-green-700"></div>
      </div>
    );
  }
  if (!isAdmin) return <Navigate to="/login" />;

  return (
    <div className="container mx-auto px-4 pb-12">
      <div className="flex items-center justify-between mb-8">
        <h2 className="text-3xl font-bold text-gray-800 flex items-center gap-2">
          <LayoutDashboard size={32} className="text-green-700" />
          Tableau de Bord des Sinistres
        </h2>
        <div className="bg-green-100 text-green-800 px-4 py-2 rounded-lg font-bold">
          {claims.length} Déclarations au total
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center p-20">
          <div className="animate-spin rounded-full h-16 w-16 border-t-4 border-b-4 border-green-700"></div>
        </div>
      ) : (
        <div className="grid gap-8">
          {claims.map((claim) => (
            <div key={claim.id} className="bg-white rounded-xl shadow-lg p-8 border-l-8 border-green-700 hover:shadow-2xl transition duration-300">
              <div className="flex justify-between items-start mb-6">
                <div>
                  <h3 className="text-2xl font-bold text-green-800 mb-1">{claim.full_name}</h3>
                  <p className="text-gray-500 font-medium">Référence: #STAR-{claim.id}-{new Date(claim.created_at).getFullYear()}</p>
                </div>
                <div className={`px-6 py-2 rounded-full font-bold uppercase text-sm shadow-sm ${
                  claim.status === 'pending' ? 'bg-yellow-100 text-yellow-800' :
                  claim.status === 'processed' ? 'bg-green-100 text-green-800' : 'bg-blue-100 text-blue-800'
                }`}>
                  {claim.status === 'pending' ? 'En attente' : claim.status === 'processed' ? 'Clôturé' : 'Révisé'}
                </div>
              </div>

              <div className="grid md:grid-cols-2 gap-8 mb-8">
                <div className="bg-green-50/50 p-5 rounded-xl border border-green-100">
                  <h4 className="font-bold text-green-900 mb-3 border-b border-green-200 pb-1">Client</h4>
                  <p className="mb-2"><strong>CIN:</strong> {claim.cin}</p>
                  <p className="mb-2"><strong>E-mail:</strong> {claim.email || 'Non renseigné'}</p>
                  <p className="mb-2"><strong>N° Police:</strong> {claim.policy_number}</p>
                  <p><strong>Tél:</strong> {claim.phone_number}</p>
                </div>
                <div className="bg-blue-50/50 p-5 rounded-xl border border-blue-100">
                  <h4 className="font-bold text-blue-900 mb-3 border-b border-blue-200 pb-1">Véhicule</h4>
                  <p>{claim.vehicle_details}</p>
                </div>
              </div>

              {claim.attachments.length > 0 && (
                <div className="mb-8">
                  <h4 className="font-bold mb-4 text-gray-700 flex items-center gap-2">
                    <Upload size={20} className="text-green-700" />
                    Documents Justificatifs:
                  </h4>
                  <div className="flex gap-4 flex-wrap">
                    {claim.attachments.map((att: any) => (
                      <a key={att.id} href={`${att.download_url}`} target="_blank" rel="noopener noreferrer" className="...">
                        <FileText size={20} />
                        {att.file_name}
                      </a>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex gap-4 border-t pt-6">
                <button onClick={() => updateStatus(claim.id, 'reviewed')} className="bg-blue-600 text-white px-6 py-2.5 rounded-lg hover:bg-blue-700 transition font-bold shadow-md">Passer en Révision</button>
                <button onClick={() => updateStatus(claim.id, 'processed')} className="bg-green-700 text-white px-6 py-2.5 rounded-lg hover:bg-green-800 transition font-bold shadow-md">Clôturer le Dossier</button>
              </div>
            </div>
          ))}
          {claims.length === 0 && (
            <div className="text-center p-20 bg-white rounded-2xl shadow-inner border-2 border-dashed border-gray-200">
              <Star size={64} className="mx-auto text-gray-200 mb-4" />
              <p className="text-xl text-gray-400 font-medium">Aucune déclaration en attente pour le moment.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const App = () => {
  // null = "checking with backend", true/false = confirmed state.
  // Never trust a client-set flag (e.g. localStorage) as the source of
  // truth - the backend's /me endpoint (which validates the httpOnly
  // JWT cookie) is the only thing that decides this.
  const [isAdmin, setIsAdmin] = useState<boolean | null>(null);

  useEffect(() => {
    axios.get(`${API_BASE_URL}/me`)
      .then(() => setIsAdmin(true))
      .catch(() => setIsAdmin(false));
  }, []);

  const handleLogin = () => setIsAdmin(true);

  const handleLogout = async () => {
    try {
      await axios.post(`${API_BASE_URL}/logout`);
    } finally {
      setIsAdmin(false);
    }
  };

  return (
    <Router>
      <div className="min-h-screen w-full bg-slate-50 pb-10">
        <Navbar isAdmin={isAdmin === true} onLogout={handleLogout} />
        <Routes>
          <Route path="/" element={<DeclarationForm />} />
          <Route path="/login" element={<Login onLogin={handleLogin} />} />
          <Route path="/admin" element={<AdminDashboard isAdmin={isAdmin} />} />
        </Routes>
      </div>
    </Router>
  );
};

export default App;
