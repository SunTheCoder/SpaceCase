const SET_USER = 'session/setUser'
const REMOVE_USER = 'session/removeUser'
const UPDATE_USER = 'session/updateUser'

const API_URL = import.meta.env.VITE_API_URL

const setUser = (user) => ({
  type: SET_USER,
  payload: user,
})

const updateUser = (updates) => ({
  type: UPDATE_USER,
  payload: updates,
});


const removeUser = () => ({
  type: REMOVE_USER,
})

// Add this helper function to get CSRF token from cookies
function getCookie(name) {
  const value = `; ${document.cookie}`
  const parts = value.split(`; ${name}=`)
  if (parts.length === 2) return parts.pop().split(';').shift()
}

// Add this function at the top with other utility functions
async function ensureCsrfToken() {
  console.log('Checking for CSRF token...');
  let token = getCookie('csrf_token');
  console.log('Initial token:', token);
  
  if (!token) {
    console.log('No token found, fetching new one...');
    const response = await fetch(`${API_URL}/api/auth/csrf`, {
      credentials: 'include'
    });
    
    if (response.ok) {
      const data = await response.json();
      token = data.csrf_token;
      console.log('New token received:', token);
    } else {
      console.error('Failed to get CSRF token');
    }
  }
  
  return token;
}

export const thunkAuthenticate = () => async (dispatch) => {
  const response = await fetch(`${API_URL}/api/auth/`, {
    credentials: 'include'
  })
  if (response.ok) {
    const data = await response.json()
    if (data.errors) {
      return
    }

    dispatch(setUser(data))
  }
}

export const thunkLogin = (credentials) => async (dispatch) => {
  const response = await fetch(`${API_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'X-CSRF-Token': getCookie('csrf_token')
    },
    body: JSON.stringify(credentials),
    credentials: 'include'
  })

  if (response.ok) {
    const data = await response.json()
    dispatch(setUser(data))
  } else if (response.status < 500) {
    const errorMessages = await response.json()
    return errorMessages
  } else {
    return { server: 'Something went wrong. Please try again' }
  }
}

export const thunkSignup = (user) => async (dispatch) => {
  try {
    const token = await ensureCsrfToken();
    if (!token) {
      throw new Error('Could not get CSRF token');
    }
    
    console.log('Making signup request with token:', token);
    const response = await fetch(`${API_URL}/api/auth/signup`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'X-CSRF-Token': token
      },
      body: JSON.stringify(user),
      credentials: 'include'
    });
    
    if (response.ok) {
      const data = await response.json();
      dispatch(setUser(data));
      return null;
    } else {
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        const errorData = await response.json();
        return errorData;
      } else {
        const text = await response.text();
        console.error('Non-JSON response:', text);
        return { error: 'Invalid server response' };
      }
    }
  } catch (error) {
    console.error('Signup error:', error);
    return { error: error.message };
  }
}

export const thunkUpdateUser = (walletAddress) => async (dispatch) => {
  try {
    const response = await fetch(`${API_URL}/api/auth/update`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCookie('csrf_token')
      },
      body: JSON.stringify({ wallet_address: walletAddress }),
      credentials: 'include'
    });

    if (response.ok) {
      const updatedUser = await response.json();
      dispatch(updateUser(updatedUser)); // Use the action creator
    } else {
      const errorData = await response.json();
      console.error('Error updating wallet:', errorData);
    }
  } catch (error) {
    console.error('Error in thunkUpdateUser:', error);
  }
};





export const thunkLogout = () => async (dispatch) => {
  await fetch(`${API_URL}/api/auth/logout`, {
    credentials: 'include'
  })
  dispatch(removeUser())
}

const initialState = { user: null }

function sessionReducer(state = initialState, action) {
  switch (action.type) {
    case SET_USER:
      return { ...state, user: action.payload }
    case UPDATE_USER:
      return {...state, user: {...state.user,...action.payload } }
    case REMOVE_USER:
      return { ...state, user: null }
    default:
      return state
  }
}

export default sessionReducer
