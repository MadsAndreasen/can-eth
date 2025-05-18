import asyncio

import pytest

async def async_add(a,b):
    await asyncio.sleep(0.1)
    return a + b

@pytest.mark.asyncio(loop_scope="module")   # loop_scope="module" is required for async tests   
async def test_async_add():
    assert await async_add(1,2) == 3