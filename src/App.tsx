import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, Link, Outlet, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  KeyRound, 
  LayoutDashboard, 
  Plus, 
  Settings as SettingsIcon, 
  PanelLeftClose, 
  PanelLeftOpen,
  Bot,
  Sparkles,
  ShieldCheck
} from 'lucide-react';
import Dashboard from './pages/Dashboard';
import NewConnection from './pages/NewConnection';
import Settings from './pages/Settings';
import McpZatten from './pages/McpZatten';
import Skills from './pages/Skills';
import Security from './pages/Security';
import Login from './pages/Login';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navigate } from 'react-router-dom';

function Layout() {
  const location = useLocation();
  const [isCollapsed, setIsCollapsed] = useState(false);

  return (
    <div className="min-h-screen bg-background flex flex-col md:flex-row">
      {/* Sidebar Recolhível */}
      <aside 
        className={`w-full border-b md:border-b-0 md:border-r border-border bg-secondary/50 p-4 md:p-5 flex flex-col justify-between transition-all duration-300 ease-in-out relative ${
          isCollapsed ? 'md:w-20' : 'md:w-64'
        }`}
      >
        <div className="flex flex-col gap-6">
          {/* Cabeçalho da Sidebar */}
          <div className={`flex items-center gap-3 ${isCollapsed ? 'justify-center' : ''}`}>
            <div className="w-9 h-9 rounded-xl bg-primary flex items-center justify-center shadow-lg shadow-primary/20 flex-shrink-0">
              <KeyRound className="text-primary-foreground" size={18} />
            </div>
            <AnimatePresence>
              {!isCollapsed && (
                <motion.div
                  initial={{ opacity: 0, width: 0 }}
                  animate={{ opacity: 1, width: 'auto' }}
                  exit={{ opacity: 0, width: 0 }}
                  transition={{ duration: 0.2 }}
                  className="overflow-hidden whitespace-nowrap"
                >
                  <h1 className="text-lg font-bold tracking-tight text-foreground">Key Manager</h1>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
          
          {/* Navegação */}
          <nav className="flex flex-col gap-1.5">
            <NavLink 
              to="/" 
              icon={<LayoutDashboard size={18} />} 
              label="Dashboard" 
              active={location.pathname === '/'} 
              isCollapsed={isCollapsed}
            />
            <NavLink 
              to="/new" 
              icon={<Plus size={18} />} 
              label="Nova Conexão" 
              active={location.pathname === '/new'} 
              isCollapsed={isCollapsed}
            />
            <NavLink 
              to="/mcp" 
              icon={<Bot size={18} />} 
              label="MCP Zatten" 
              active={location.pathname === '/mcp'} 
              isCollapsed={isCollapsed}
            />
            <NavLink 
              to="/skills" 
              icon={<Sparkles size={18} />} 
              label="Skills" 
              active={location.pathname === '/skills'} 
              isCollapsed={isCollapsed}
            />
            <NavLink 
              to="/security" 
              icon={<ShieldCheck size={18} />} 
              label="Segurança" 
              active={location.pathname === '/security'} 
              isCollapsed={isCollapsed}
            />
            <NavLink 
              to="/settings" 
              icon={<SettingsIcon size={18} />} 
              label="Configurações" 
              active={location.pathname === '/settings'} 
              isCollapsed={isCollapsed}
            />
          </nav>
        </div>

        {/* Rodapé da Sidebar */}
        <div className={`pt-4 border-t border-border/50 hidden md:flex items-center ${isCollapsed ? 'justify-center' : 'justify-between'} text-xs text-zinc-500`}>
          {!isCollapsed && <span>v1.0.0</span>}
          <button
            type="button"
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="p-1 rounded hover:bg-white/5 hover:text-zinc-300 transition-colors cursor-pointer"
            title={isCollapsed ? 'Expandir barra lateral' : 'Recolher barra lateral'}
          >
            {isCollapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
          </button>
        </div>
      </aside>

      {/* Conteúdo Principal */}
      <main className="flex-1 relative overflow-hidden">
        <div className="h-full p-8 overflow-y-auto">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

function NavLink({ 
  to, 
  icon, 
  label, 
  active, 
  isCollapsed 
}: { 
  to: string; 
  icon: React.ReactNode; 
  label: string; 
  active: boolean;
  isCollapsed: boolean;
}) {
  return (
    <Link
      to={to}
      title={isCollapsed ? label : undefined}
      className={`flex items-center gap-3 px-3.5 py-3 rounded-xl transition-all duration-300 relative overflow-hidden group ${
        isCollapsed ? 'justify-center' : ''
      } ${
        active ? 'text-primary-foreground font-medium' : 'text-zinc-400 hover:text-foreground hover:bg-white/5'
      }`}
    >
      {active && (
        <motion.div
          layoutId="active-nav"
          className="absolute inset-0 bg-primary z-0"
          initial={false}
          transition={{ type: 'spring', stiffness: 300, damping: 30 }}
        />
      )}
      <div className="relative z-10 flex items-center gap-3">
        <span className="flex-shrink-0">{icon}</span>
        {!isCollapsed && (
          <span className="whitespace-nowrap overflow-hidden text-ellipsis">{label}</span>
        )}
      </div>
    </Link>
  );
}

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />;
}

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
            <Route index element={<Dashboard />} />
            <Route path="new" element={<NewConnection />} />
            <Route path="mcp" element={<McpZatten />} />
            <Route path="skills" element={<Skills />} />
            <Route path="security" element={<Security />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
