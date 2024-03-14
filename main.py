import asyncio
import sys

import questionary
from questionary import Choice
from loguru import logger
from utils import Account


async def main(module):
    with open('keys.txt', "r") as f:
        keys = [row.strip() for row in f]
        if not keys:
            logger.warning('НЕ ВСТАВЛЕНЫ КЛЮЧИ В КЕЙС.ТХТ')


    for id, pair in enumerate(keys):
        key_pair = pair.split(':')
        if len(key_pair) == 2:
            key, address = key_pair
        else:
            key, address = *key_pair, None
        account = Account(key, id=id+1, address_to=address)
        match module:
            case 'claim':
                await account.claim()
            case _:
                await account.transfer()


if __name__ == '__main__':
    modules = questionary.select(
        "Выберите модули для работы...",
        choices=[
            Choice(" 1) КЛЕЙМ AEVO", 'claim'),
            Choice(" 2) ТРАНСФЕР AEVO", 't'),
            Choice(" 3) ВЫХОД", 'e'),
        ],
        qmark="",
        pointer="⟹",
    ).ask()
    if modules == 'e':
        sys.exit()
    asyncio.run(main(modules))
