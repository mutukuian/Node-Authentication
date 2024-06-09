import React, { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

function Home() {
    const [user, setUser] = useState(null);
    const [alertVisible, setAlertVisible] = useState(false);
    const navigate = useNavigate();
    const timeoutRef = useRef(null);

    useEffect(() => {
        const fetchUser = async () => {
            const token = localStorage.getItem('token');
            if (!token) {
                navigate('/login');
                return;
            }

            try {
                const response = await axios.get('http://localhost:3001/me', {
                    headers: { Authorization: `Bearer ${token}` }
                });
                setUser(response.data);
                handleTokenExpiry(token);
            } catch (error) {
                console.error('Error fetching user data:', error);
                localStorage.removeItem('token');
                navigate('/login');
            }
        };

        fetchUser();

        return () => {
            clearTimeout(timeoutRef.current);
        };
    }, [navigate]);

    const handleTokenExpiry = (token) => {
        const decodedToken = JSON.parse(atob(token.split('.')[1]));
        const expiryTime = decodedToken.exp * 1000;
        const currentTime = Date.now();
        const timeLeft = expiryTime - currentTime;

        if (timeLeft > 10000) {
            timeoutRef.current = setTimeout(() => {
                setAlertVisible(true);
            }, timeLeft - 10000);
        } else {
            setAlertVisible(true);
        }
    };

    const refreshToken = async () => {
        const refreshToken = localStorage.getItem('refreshToken');
        if (!refreshToken) {
            navigate('/login');
            return;
        }

        try {
            const response = await axios.post('http://localhost:3001/refresh-token', { refreshToken });
            localStorage.setItem('token', response.data.accessToken);
            setAlertVisible(false);
            handleTokenExpiry(response.data.accessToken);
        } catch (error) {
            console.error('Error refreshing token:', error);
            localStorage.removeItem('token');
            navigate('/login');
        }
    };

    if (!user) {
        return <p>Loading...</p>;
    }

    return (
        <div>
            <h2>Welcome, {user.name}</h2>
            <p>This is the home page.</p>
            {alertVisible && (
                <div className="alert alert-warning">
                    <p>Your session is about to expire. Please refresh your token.</p>
                    <button onClick={refreshToken} className="btn btn-primary">Refresh Token</button>
                </div>
            )}
        </div>
    );
}

export default Home;
