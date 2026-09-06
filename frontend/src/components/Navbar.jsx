import { Link, useLocation } from 'react-router-dom'
import { useEffect, useState } from 'react'
import axios from 'axios'

function Navbar() {
  const location = useLocation()
  const [status, setStatus] = useState('checking')

  useEffect(() => {
    axios.get('/health')
      .then(() => setStatus('online'))
      .catch(() => setStatus('offline'))
  }, [])

  const navLink = (path, label) => (
    <Link
      to={path}
      className={`text-sm px-3 py-1.5 rounded-lg transition ${
        location.pathname === path
          ? 'bg-purple-600 text-white'
          : 'text-gray-400 hover:text-white'
      }`}
    >
      {label}
    </Link>
  )

  return (
    <nav className="bg-gray-900 border-b border-gray-800 px-6 py-3 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-2xl">🛡️</span>
          <div>
            <span className="text-lg font-bold text-white">CodeSentinel</span>
            <span className="ml-2 text-xs bg-purple-600 text-white px-2 py-0.5 rounded-full">AI</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {navLink('/', 'Dashboard')}
          {navLink('/reviews', 'Reviews')}
        </div>

        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${status === 'online' ? 'bg-green-400' : 'bg-red-400'}`}></div>
          <span className={`text-xs ${status === 'online' ? 'text-green-400' : 'text-red-400'}`}>
            {status === 'online' ? 'API Online' : 'API Offline'}
          </span>
        </div>
      </div>
    </nav>
  )
}

export default Navbar