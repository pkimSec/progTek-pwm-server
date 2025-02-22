# tests/test_rate_limit.py
import time

def test_rate_limiting(client):
    """Test that rate limiting is working"""
    # Make 21 requests in quick succession
    for i in range(21):
        response = client.post('/api/login', json={
            'email': 'test@example.com',
            'password': 'password123'
        })
        
        if i < 20:
            # First 20 requests should get through (even if login fails)
            assert response.status_code in [400, 401]  # Either missing fields or invalid credentials
        else:
            # 21st request should be rate limited
            assert response.status_code == 429
            assert b'Too Many Requests' in response.data

def test_rate_limit_reset(client):
    """Test that rate limit resets after the time window"""
    # Make 20 requests (hitting the limit)
    for _ in range(20):
        client.post('/api/login', json={
            'email': 'test@example.com',
            'password': 'password123'
        })
    
    # Wait for 60 seconds (rate limit window)
    time.sleep(60)
    
    # Should be able to make another request
    response = client.post('/api/login', json={
        'email': 'test@example.com',
        'password': 'password123'
    })
    assert response.status_code in [400, 401]  # Not rate limited