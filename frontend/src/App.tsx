import React from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Header from './components/Header'

import Overview           from './pages/Overview'
import TelemetryCenter    from './pages/TelemetryCenter'
import DetectionEngines   from './pages/DetectionEngines'
import SubEngines         from './pages/SubEngines'
import ThreatIntelligence from './pages/ThreatIntelligence'
import NetworkTopology    from './pages/NetworkTopology'
import IncidentCenter     from './pages/IncidentCenter'
import InvestigationDetail from './pages/InvestigationDetail'
import ContainmentCenter  from './pages/ContainmentCenter'

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen overflow-hidden bg-bg text-white">
        <Sidebar />
        <div className="flex-1 flex flex-col overflow-hidden">
          <Header />
          <main className="flex-1 overflow-y-auto">
            <Routes>
              <Route path="/"                  element={<Overview />} />
              <Route path="/telemetry"         element={<TelemetryCenter />} />
              <Route path="/engines"           element={<DetectionEngines />} />
              <Route path="/sub-engines"       element={<SubEngines />} />
              <Route path="/threat-intel"      element={<ThreatIntelligence />} />
              <Route path="/topology"          element={<NetworkTopology />} />
              <Route path="/incidents"         element={<IncidentCenter />} />
              <Route path="/incidents/:id"     element={<InvestigationDetail />} />
              <Route path="/containment"       element={<ContainmentCenter />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  )
}
