import { useState } from 'react';
import MatrixRain from '../../features/matrixRain/MatrixRain';
import GlassCard from '../../components/ui/GlassCard';
import GlassButton from '../../components/ui/GlassButton';
import GlassInput from '../../components/ui/GlassInput';
import './MainScreen.css';

function MainScreen({ onBack }) {
  const [url, setUrl] = useState('');
  
  // Состояния для чекбоксов
  const [enableLogs, setEnableLogs] = useState(true);      // Включить логи
  const [autoRefresh, setAutoRefresh] = useState(false);   // Автообновление
  const [darkMode, setDarkMode] = useState(true);          // Тёмная тема
  const [notifications, setNotifications] = useState(true); // Уведомления

  // Обработчик изменения поля ввода
  const handleUrlChange = (e) => {
    setUrl(e.target.value);
  };

  // Обработчик кнопки "Старт"
  const handleStart = () => {
    if (url.trim()) {
      console.log('Запуск анализа ссылки:', url);
      // здесь будет логика запуска
      alert(`Запущен анализ: ${url}`);
    } else {
      alert('Введите ссылку!');
    }
  };

  // Обработчик кнопки "Очистить"
  const handleClear = () => {
    setUrl('');
    console.log('Поле очищено');
  };

  return (
    <>
      <MatrixRain />

    <div className="main-screen">
      
      {/* Заголовок панели */}
      <header className="main-screen__header">
        <h1 className="main-screen__title">Панель управления</h1>
        <GlassButton size="small" onClick={onBack}>
          Назад
        </GlassButton>
      </header>

      {/* Основной контент */}
      <div className="main-screen__content">
        
        {/* Секция 1: Ввод ссылки */}
        <GlassCard title="Анализ ссылки" size="large">
          <div className="main-screen__section">
            
            {/* Поле ввода ссылки */}
            <GlassInput
              label="Введите URL для анализа"
              placeholder="https://example.com"
              value={url}
              onChange={handleUrlChange}
              type="text"
              size="large"
            />

            {/* Кнопки управления */}
            <div className="main-screen__row">
              <GlassButton size="large" onClick={handleStart}>
                Старт
              </GlassButton>
              <GlassButton size="large" onClick={handleClear}>
                Очистить
              </GlassButton>
              <GlassButton size="large" disabled>
                Экспорт
              </GlassButton>
            </div>

          </div>
        </GlassCard>

        {/* Секция 2: Настройки */}
        <GlassCard title="Настройки">
          <div className="main-screen__section">
            <h3 className="main-screen__section-title">Параметры</h3>
            
            {/* Группа чекбоксов */}
            <div className="main-screen__checkbox-group">
              
              {/* Чекбокс: Включить логи */}
              <label className="main-screen__checkbox-item">
                <input
                  type="checkbox"
                  className="main-screen__checkbox"
                  checked={enableLogs}
                  onChange={(e) => setEnableLogs(e.target.checked)}
                />
                <span className="main-screen__checkbox-label">
                  Включить логирование
                </span>
              </label>

              {/* Чекбокс: Автообновление */}
              <label className="main-screen__checkbox-item">
                <input
                  type="checkbox"
                  className="main-screen__checkbox"
                  checked={autoRefresh}
                  onChange={(e) => setAutoRefresh(e.target.checked)}
                />
                <span className="main-screen__checkbox-label">
                  Автоматическое обновление
                </span>
              </label>

              {/* Чекбокс: Тёмная тема */}
              <label className="main-screen__checkbox-item">
                <input
                  type="checkbox"
                  className="main-screen__checkbox"
                  checked={darkMode}
                  onChange={(e) => setDarkMode(e.target.checked)}
                />
                <span className="main-screen__checkbox-label">
                  Тёмная тема
                </span>
              </label>

              {/* Чекбокс: Уведомления */}
              <label className="main-screen__checkbox-item">
                <input
                  type="checkbox"
                  className="main-screen__checkbox"
                  checked={notifications}
                  onChange={(e) => setNotifications(e.target.checked)}
                />
                <span className="main-screen__checkbox-label">
                  Уведомления
                </span>
              </label>

            </div>
          </div>
        </GlassCard>

        {/* Секция 3: Дополнительные кнопки */}
        <GlassCard title="Действия">
          <div className="main-screen__section">
            <h3 className="main-screen__section-title">Быстрые действия</h3>
            
            {/* Ряд с кнопками */}
            <div className="main-screen__row">
              <GlassButton size="small">Сканировать</GlassButton>
              <GlassButton size="small">Анализировать</GlassButton>
              <GlassButton size="small">Отчёт</GlassButton>
              <GlassButton size="small">Настройки</GlassButton>
            </div>

            {/* Ещё один ряд кнопок */}
            <div className="main-screen__row">
              <GlassButton size="small" disabled>
                Архив
              </GlassButton>
              <GlassButton size="small" disabled>
                Статистика
              </GlassButton>
              <GlassButton size="small" disabled>
                Помощь
              </GlassButton>
            </div>
          </div>
        </GlassCard>
      </div>
    </div>
    </>
  );
}

export default MainScreen;