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


import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
