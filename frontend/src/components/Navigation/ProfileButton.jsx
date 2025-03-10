import { useDispatch, useSelector } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import { Button } from '@chakra-ui/react'; // For consistent styling with Chakra
import { FaUserCircle } from 'react-icons/fa';
import { MenuRoot, MenuTrigger, MenuContent, MenuItem } from '@/components/ui/menu';
import { thunkLogout } from '../../redux/session';
import OpenModalMenuItem from './OpenModalMenuItem';
import LoginFormModal from '../LoginFormModal';
import SignupFormModal from '../SignupFormModal';

function ProfileButton() {
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const user = useSelector((store) => store.session.user);

  const logout = (e) => {
    e.preventDefault();
    dispatch(thunkLogout());
    navigate('/'); // Redirect to the home page
  };

  return (
    <MenuRoot>
      <MenuTrigger asChild>
        <Button variant="ghost" m={1}
        p={1} size="sm" borderRadius="4xl">
        <FaUserCircle />
        </Button>
      </MenuTrigger>
      <MenuContent
         style={{
          listStyle: 'none', // Ensure no bullets appear
          padding: 0, // Remove default padding
          margin: 0, // Remove default margin
        }}
      bg="rgb(220, 151, 222)" 
      _dark={{bg:"rgb(71, 39, 72)"}}

      
      >
        {user ? (
          <>
            <MenuItem 
            
            value="username" isDisabled>
              Hi, {user.username}! 👋🏾
            </MenuItem>
            <MenuItem value="email" isDisabled>
              {user.email}
            </MenuItem>
            <MenuItem value="logout" onClick={logout}>
              Log Out
            </MenuItem>
          </>
        ) : (
          <>
            <MenuItem 
            value="login">
              <OpenModalMenuItem
                itemText="Log In"
                modalComponent={<LoginFormModal />}
              />
            </MenuItem>
            <MenuItem value="signup">
              <OpenModalMenuItem
                itemText="Sign Up"
                modalComponent={<SignupFormModal />}
              />
            </MenuItem>
          </>
        )}
      </MenuContent>
    </MenuRoot>
  );
}

export default ProfileButton;
