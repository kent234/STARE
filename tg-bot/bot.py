import os
import logging
from dotenv import load_dotenv

from telegram import Update, ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# 1. Загружаем токен из файла .env
load_dotenv()
TOKEN = os.getenv('BOT_TOKEN')

if not TOKEN:
    logging.error("Токен не найден! Проверьте файл .env")
    exit(1)

# 2. Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# 3. Обработчик команды /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Создаем клавиатуру с одной кнопкой "Начать" на всю ширину
    keyboard = [[KeyboardButton("Начать")]]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True, one_time_keyboard=True)
    
    await update.message.reply_text(
        "текст приветствия вставить сюда",
        reply_markup=reply_markup
    )

# 4. Обработчик нажатия на текстовую кнопку "Начать"
async def handle_start_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.text == "Начать":
        # ReplyKeyboardRemove() убирает кастомную клавиатуру и возвращает обычную строку ввода
        await update.message.reply_text(
            "бот все еще в разработке",
            reply_markup=ReplyKeyboardRemove()
        )

# 5. Обработчик команды /guide
async def guide(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("тут пока ничего нет")

# 6. Основная функция запуска
def main():
    # Создаем приложение (синтаксис для v20+)
    application = Application.builder().token(TOKEN).build()

    # Регистрируем обработчики команд
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("guide", guide))
    
    # Регистрируем обработчик текстовых сообщений для кнопки "Начать"
    # filters.Regex("^Начать$") гарантирует, что сработает только на точное совпадение
    application.add_handler(MessageHandler(filters.TEXT & filters.Regex("^Начать$"), handle_start_button))

    logger.info("Бот запущен и готов к работе!")
    # Запускаем polling (получение обновлений)
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()