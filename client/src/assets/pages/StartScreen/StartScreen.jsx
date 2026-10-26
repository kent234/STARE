import React from 'react';
import MatrixRain from '../../features/matrixRain/MatrixRain';
import AsciiEarth from '../../features/asciiEarth/AsciiEarth';
import GlassCard from '../../components/ui/GlassCard';
import GlassButton from '../../components/ui/GlassButton';
import './StartScreen.css';

function StartScreen({ onStart }) {
  return (
    <>
      <MatrixRain />
      
      {/* Основной контент страницы (поверх матрицы) */}
      <div className="start-screen">
        
        {/* Карточка с вращающейся ASCII-землёй */}
        <div className="start-screen__earth-wrapper">
          <GlassCard size="large">
            <AsciiEarth />
          </GlassCard>
        </div>

        {/* Карточка с описанием проекта */}
        <div className="start-screen__description-wrapper">
          <GlassCard>
            <p className="start-screen__description">
              Добро пожаловать в битбокс валеры курочкина, тут крч будет описание а пока я зачту вам биток: 
              ОПА-НА!!! 🤪🤪🤪🚜🌻🌻 ПОГНАЛИ НА РАЙОНЕ!!! 🐸🐸🐸
              бЭЭЭэЭэМЦ!!! 💥💥💥💥💥 (грязь летит) 🐷🐷🐷
              пшшшшшшшшшшшшшшшшшшшшшш 🐍🐍🐍💦
              ТЫЦ!!! 🥁💃🕺 ТЫЦ!!! 🥁💃🕺
              🌹🌹🌹 ЛЮБОВЬ И БИТБОКС 2007 🌹🌹🌹
              💩💩💩 эТО ЧёТКо 💩💩💩
              б
              у
              м
              ???!!! 🤯🤯🤯
              ААААААААААААААА 🤡🤡🤡 ПЫЩЬ ПЫЩЬ ПЫЩЬ 🔫🔫🔫
              тс-тс-тс-тс-тс-тс-тс ⚡⚡⚡👽👽
              🤑🤑🤑 спс за лайк 🤑🤑🤑
            </p>
          </GlassCard>
        </div>

        {/* Кнопка "Начать" */}
        <div className="start-screen__button-wrapper">
          <GlassButton size="large" onClick={onStart}>
            Начать
          </GlassButton>
        </div>

      </div>
    </>
  );
}

export default StartScreen;