import { useState } from 'react';
import StartScreen from './assets/pages/StartScreen/StartScreen';
import MainScreen from './assets/pages/MainScreen/MainScreen';
function App() {
  const [currentScreen, setCurrentScreen] = useState('start');

  const handleStart = () => {
    setCurrentScreen('panel');
    console.log('Переход на панель управления');
  };

  const handleBack = () => {
    setCurrentScreen('start');
    console.log('Возврат на стартовую страницу');
  };

  return (
    <>
      {currentScreen === 'start' && (
        <StartScreen onStart={handleStart} />
      )}
      
      {currentScreen === 'panel' && (
        <MainScreen onBack={handleBack} />
      )}
    </>
  );
}

export default App;