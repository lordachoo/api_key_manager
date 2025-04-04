# TODO LIST

## To Do

- Add live examples to the README.md 
    - Maybe an ASCIINEMA video?
- Add BOLD note about hiding your output from HIST via 
   - Space before command , e.g ` ./api_key_manager`


## Done
~~- Add version #define~~
~~- Add ability to remove an API-KEY entry (after providing successful master key decrypt)~~
~~- Bug with adding a key repeating ./api_key_manager -l! in the middle of the repeated command?~~
```bash
 root@pixstor-NAS:/mmfs1/data/scripts/api_key_manager # ./api_key_manager -a "A KEY!!!"
./api_key_manager -a "A KEY./api_key_manager -l!"          <---- ??
Enter master key: xxxxxx
Enter API key: akeyhere123098120948019
API key added successfully with ID: 4
```
    ~~- This is likely because of the "!" which repeated commands within BASH. Could not replicate without the "!"~~
- Implement a way for the password to not show up visually in terminal as you type it 
   - Done via termios, changing the terminals to disallow echo when typing in master password/key. 