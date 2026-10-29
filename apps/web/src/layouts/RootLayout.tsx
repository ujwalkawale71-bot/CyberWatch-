import { Outlet } from 'react-router-dom'
import { Navbar } from '../components/navigation/Navbar'
import { Footer } from '../components/sections/Footer'

export function RootLayout() {
  return (
    <div className="min-h-screen flex flex-col bg-white">
      <Navbar />
      <main className="flex-1">
        <Outlet />
      </main>
      <Footer />
    </div>
  )
}

