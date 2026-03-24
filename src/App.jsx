import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'

function App() {
  // 1. Create a state variable to hold the string Rust returns
  const [appInfo, setAppInfo] = useState('0')

  // 2. On mount, call invoke and store the result
  useEffect(() => {
    invoke('app_info').then((info) => {
      setAppInfo(info)
    })
  }, [])

  // 3. Render it
  return (
    <div>
      {appInfo}
    </div>
  )
}

export default App